import os
import socket
import config
import crypto_utils
import game_logic
import protocol


# player id assignment
def receive_player_id(sock):
    # Pre: sock is connected and house has sent this player's id
    # Post: returns the assigned player id
    raw = protocol.recv_frame(sock)
    player_id = raw.decode("utf-8")
    print(f"[player] assigned identity: {player_id}")
    return player_id


# oaep key loading
def load_oaep_key():
    # Pre: house OAEP public key exists
    # Post: returns the house RSA-OAEP public key
    path = os.path.join(config.KEYS_DIR, config.HOUSE_OAEP_PUBLIC_KEY)
    return crypto_utils.load_rsa_public_key(path)

# signing key loading
def load_signing_keys(player_id, scheme):
    # Pre: player_id and scheme are valid, and matching key files exist
    # Post: returns the player private signing key and house public signing key
    signing_priv_file = f"{player_id}_{scheme}_private.pem"
    house_signing_pub_file = f"house_{scheme}_public.pem"

    signing_priv_path = os.path.join(config.KEYS_DIR, signing_priv_file)
    house_signing_pub_path = os.path.join(config.KEYS_DIR, house_signing_pub_file)

    if scheme == config.SIG_SCHEME_RSA:
        player_signing_priv = crypto_utils.load_rsa_private_key(signing_priv_path)
        house_signing_pub = crypto_utils.load_rsa_public_key(house_signing_pub_path)
    else:
        player_signing_priv = crypto_utils.load_dsa_private_key(signing_priv_path)
        house_signing_pub = crypto_utils.load_dsa_public_key(house_signing_pub_path)

    return player_signing_priv, house_signing_pub

# session key exchange
def send_session_key(sock, house_oaep_pub):
    # Pre: sock is connected and the house OAEP public key is loaded
    # Post: sends the encrypted AES session key and returns the raw session key
    session_key = os.urandom(config.AES_KEY_SIZE)

    encrypted_key = crypto_utils.rsa_oaep_encrypt(session_key, house_oaep_pub)
    protocol.send_frame(sock, encrypted_key)

    print(f"[player] session key sent ({len(session_key)} bytes, RSA-OAEP encrypted)")
    return session_key


# signed hello
def send_signed_hello(sock, player_id, session_key, player_signing_priv, scheme):
    # Pre: session key and player signing key are ready
    # Post: sends a signed and encrypted hello message to house
    msg = protocol.build_message(
        protocol.MSG_SESSION_KEY,
        player_id,
        {"player_id": player_id},
    )

    msg_bytes = protocol.serialize(msg)
    signature = protocol.sign(msg_bytes, player_signing_priv, scheme)
    bundle = msg_bytes + b"||" + signature
    ciphertext = crypto_utils.aes_cbc_encrypt(bundle, session_key)
    protocol.send_frame(sock, ciphertext)

    print(f"[player] signed hello sent (scheme: {scheme.upper()})")


# scheme announcement
def receive_scheme_announcement(sock, session_key):
    # Pre: session key is active and house has sent the chosen scheme
    # Post: returns the signature scheme for this game
    ciphertext = protocol.recv_frame(sock)
    scheme = crypto_utils.aes_cbc_decrypt(ciphertext, session_key).decode("utf-8")

    if scheme not in config.VALID_SIG_SCHEMES:
        raise ValueError(f"invalid scheme received: {scheme}")

    print(f"[player] scheme announced by house: {scheme.upper()}")
    return scheme


# house message receiving
def receive_house_message(sock, session_key, house_signing_pub, scheme, nonce_tracker):
    # Pre: session key, house signing key, and scheme are valid
    # Post: returns a verified message from house
    ciphertext = protocol.recv_frame(sock)

    bundle = crypto_utils.aes_cbc_decrypt(ciphertext, session_key)
    msg_bytes, signature = bundle.split(b"||", 1)

    if not protocol.verify(msg_bytes, signature, house_signing_pub, scheme):
        raise ValueError("house signature verification failed")

    msg = protocol.deserialize(msg_bytes)

    if not nonce_tracker.check_and_record(msg["nonce"], msg["timestamp"]):
        raise ValueError("replay or stale message from house rejected")

    return msg


# hand receiving
def receive_hand(sock, session_key, house_signing_pub, scheme, nonce_tracker):
    # Pre: house has sent a signed hand message
    # Post: returns this player's hand
    msg = receive_house_message(
        sock,
        session_key,
        house_signing_pub,
        scheme,
        nonce_tracker,
    )

    if msg["type"] != protocol.MSG_HAND:
        raise ValueError(f"expected hand message, got: {msg['type']}")

    hand = msg["payload"]["cards"]
    print(f"[player] hand received: {hand}")
    return hand


# card selection
def prompt_card(hand, round_num):
    # Pre: hand contains the cards still available to play
    # Post: returns a valid card from the hand
    print(f"[player] round {round_num} - your remaining cards: {hand}")

    while True:
        raw = input("[player] pick a card: ").strip()

        try:
            card = int(raw)

        except ValueError:
            print("[player] enter a number")
            continue

        if not game_logic.validate_choice(card, hand):
            print(f"[player] {card} is not in your hand - pick from {hand}")
            continue

        return card


# move sending
def send_move(sock, player_id, card, session_key, player_signing_priv, scheme):
    # Pre: card is valid, and session/signing keys are ready
    # Post: sends the player's signed and encrypted move
    msg = protocol.build_message(
        protocol.MSG_MOVE,
        player_id,
        {"card": card},
    )

    msg_bytes = protocol.serialize(msg)
    signature = protocol.sign(msg_bytes, player_signing_priv, scheme)

    bundle = msg_bytes + b"||" + signature
    ciphertext = crypto_utils.aes_cbc_encrypt(bundle, session_key)

    protocol.send_frame(sock, ciphertext)

    print(f"[player] played {card} (signed, encrypted)")


# round result receiving

def receive_round_result(sock, session_key, house_signing_pub, scheme, nonce_tracker, round_num):
    # Pre: house has sent a signed round result
    # Post: prints and returns the round result
    msg = receive_house_message(
        sock,
        session_key,
        house_signing_pub,
        scheme,
        nonce_tracker,
    )

    if msg["type"] != protocol.MSG_ROUND_RESULT:
        raise ValueError(f"expected round_result message, got: {msg['type']}")

    result = msg["payload"]["result"]

    print(f"[player] round {round_num} result: {result}")
    return result


# one round of play
def play_round(sock, player_id, hand, session_key, player_signing_priv,
               house_signing_pub, scheme, nonce_tracker, round_num):
    # Pre: hand has at least one card and keys are loaded
    # Post: sends one move, receives the result, and removes the played card
    card = prompt_card(hand, round_num)

    send_move(
        sock,
        player_id,
        card,
        session_key,
        player_signing_priv,
        scheme,
    )

    hand.remove(card)

    result = receive_round_result(
        sock,
        session_key,
        house_signing_pub,
        scheme,
        nonce_tracker,
        round_num,
    )

    return result


# session key cleanup
def destroy_session_key(session_key):
    # Pre: session_key is bytes or None
    # Post: clears the session key reference
    if session_key is None:
        return

    session_key = b"\x00" * config.AES_KEY_SIZE
    del session_key
    print("[player] session key destroyed")


def main():
    # Pre: config has valid server settings and key file names
    # Post: connects to house, loads keys, and shuts down cleanly
    print("[player] Secure Internet Poker - Player client")


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    session_key = None

    try:
        try:
            house_oaep_pub = load_oaep_key()

        except FileNotFoundError as e:
            print(f"[player] ERROR: missing key file ({e}) - run generate_keys.py first")
            return

        sock.connect((config.HOST, config.PORT))
        print(f"[player] connected to house at {config.HOST}:{config.PORT}")

        player_id = receive_player_id(sock)
        print(f"[player] you are {player_id}")

        session_key = send_session_key(sock, house_oaep_pub)

        # House announces the scheme after the AES key is set.
        scheme = receive_scheme_announcement(sock, session_key)

        try:
            player_signing_priv, house_signing_pub = load_signing_keys(player_id, scheme)
            print("[player] signing keys loaded")

        except FileNotFoundError as e:
            print(f"[player] ERROR: missing key file ({e}) - run generate_keys.py first")
            return

        send_signed_hello(
            sock,
            player_id,
            session_key,
            player_signing_priv,
            scheme,
        )

        nonce_tracker = protocol.NonceTracker()

        hand = receive_hand(
            sock,
            session_key,
            house_signing_pub,
            scheme,
            nonce_tracker,
        )

        for round_num in range(1, game_logic.NUM_ROUNDS + 1):
            play_round(
                sock,
                player_id,
                hand,
                session_key,
                player_signing_priv,
                house_signing_pub,
                scheme,
                nonce_tracker,
                round_num,
            )

        # receive winner announcement
        msg = receive_house_message(
            sock,
            session_key,
            house_signing_pub,
            scheme,
            nonce_tracker,
        )

        if msg["type"] != protocol.MSG_WINNER:
            raise ValueError(f"expected winner message, got: {msg['type']}")

        winner = msg["payload"]["winner"]
        results = msg["payload"]["results"]

        print(f"[player] game over - results: {results}")
        print(f"[player] winner: {winner}")

    except OSError as e:
        print(f"[player] connection error: {e}")

    except ValueError as e:
        print(f"[player] protocol error: {e}")

    finally:
        destroy_session_key(session_key)
        sock.close()
        print("[player] disconnected")


if __name__ == "__main__":
    main()