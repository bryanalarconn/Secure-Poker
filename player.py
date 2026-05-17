import os
import socket
import config
import crypto_utils
import protocol


# signature scheme selection
def prompt_signature_scheme():
    # Pre: none
    # Post: returns the selected signature scheme
    print("[player] Select signature scheme for this game:")
    print("  1 - RSA (PSS)")
    print("  2 - DSA")

    while True:
        choice = input("[player] enter 1 or 2: ").strip()

        if choice == "1":
            return config.SIG_SCHEME_RSA

        if choice == "2":
            return config.SIG_SCHEME_DSA

        print("[player] invalid choice - enter 1 or 2")


# player id assignment
def receive_player_id(sock):
    # Pre: sock is connected and house has sent this player's id
    # Post: returns the assigned player id
    raw = protocol.recv_frame(sock)
    player_id = raw.decode("utf-8")
    print(f"[player] assigned identity: {player_id}")
    return player_id


# key loading
def load_keys(player_id, scheme):
    # Pre: key files exist, and player_id and scheme are valid
    # Post: returns the house OAEP public key, player private signing key, and house public signing key
    house_oaep_pub = crypto_utils.load_rsa_public_key(
        os.path.join(config.KEYS_DIR, config.HOUSE_OAEP_PUBLIC_KEY)
    )

    signing_priv_file = f"{player_id}_{scheme}_private.pem"
    house_signing_pub_file = f"house_{scheme}_public.pem"

    if scheme == config.SIG_SCHEME_RSA:
        player_signing_priv = crypto_utils.load_rsa_private_key(
            os.path.join(config.KEYS_DIR, signing_priv_file)
        )
        house_signing_pub = crypto_utils.load_rsa_public_key(
            os.path.join(config.KEYS_DIR, house_signing_pub_file)
        )
    else:
        player_signing_priv = crypto_utils.load_dsa_private_key(
            os.path.join(config.KEYS_DIR, signing_priv_file)
        )
        house_signing_pub = crypto_utils.load_dsa_public_key(
            os.path.join(config.KEYS_DIR, house_signing_pub_file)
        )

    return house_oaep_pub, player_signing_priv, house_signing_pub

# session key exchange
def send_session_key(sock, house_oaep_pub):
    # Pre: sock is connected and house_oaep_pub is the House RSA-OAEP public key
    # Post: returns the generated session key and sends its encrypted form to House
    session_key = os.urandom(config.AES_KEY_SIZE)  # 32 bytes from OS CSPRNG (NIST SP 800-90A)

    encrypted_key = crypto_utils.rsa_oaep_encrypt(session_key, house_oaep_pub)
    protocol.send_frame(sock, encrypted_key)

    print(f"[player] session key sent ({len(session_key)} bytes, RSA-OAEP encrypted)")
    return session_key


# signed hello
def send_signed_hello(sock, player_id, session_key, player_signing_priv, scheme):
    # Pre: sock is connected, session_key is 32 bytes, player_signing_priv is loaded
    # Post: sends a signed and AES-encrypted hello message to House
    msg = protocol.build_message(
        protocol.MSG_SESSION_KEY,
        player_id,
        {"player_id": player_id},
    )
    msg_bytes = protocol.serialize(msg)
    # sign-then-encrypt: sign the plaintext first, then encrypt the bundle
    signature = protocol.sign(msg_bytes, player_signing_priv, scheme)
    bundle = msg_bytes + b"||" + signature

    ciphertext = crypto_utils.aes_cbc_encrypt(bundle, session_key)
    protocol.send_frame(sock, ciphertext)

    print(f"[player] signed hello sent (scheme: {scheme.upper()})")

# receive a signed message from house
def receive_house_message(sock, session_key, house_signing_pub, scheme, nonce_tracker):
    # Pre: sock is connected, session_key is 32 bytes, house_signing_pub is loaded
    # Post: returns the verified and deserialized message dict
    ciphertext = protocol.recv_frame(sock)

    bundle = crypto_utils.aes_cbc_decrypt(ciphertext, session_key)
    msg_bytes, signature = bundle.split(b"||", 1)

    # signature first — never trust any field before authentication
    if not protocol.verify(msg_bytes, signature, house_signing_pub, scheme):
        raise ValueError("house signature verification failed")

    msg = protocol.deserialize(msg_bytes)

    if not nonce_tracker.check_and_record(msg["nonce"], msg["timestamp"]):
        raise ValueError("replay or stale message from house rejected")

    return msg


# hand receiving
def receive_hand(sock, session_key, house_signing_pub, scheme, nonce_tracker):
    # Pre: session key and house signing key are loaded, nonce tracker is fresh
    # Post: returns the hand as a list of ints and prints the dealt cards
    msg = receive_house_message(sock, session_key, house_signing_pub, scheme, nonce_tracker)

    if msg["type"] != protocol.MSG_HAND:
        raise ValueError(f"expected hand message, got: {msg['type']}")

    hand = msg["payload"]["cards"]
    print(f"[player] hand received: {hand}")
    return hand


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

    scheme = prompt_signature_scheme()
    print(f"[player] signature scheme: {scheme.upper()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    session_key = None

    try:
        sock.connect((config.HOST, config.PORT))
        print(f"[player] connected to house at {config.HOST}:{config.PORT}")

        player_id = receive_player_id(sock)
        print(f"[player] you are {player_id}")

        try:
            house_oaep_pub, player_signing_priv, house_signing_pub = load_keys(player_id, scheme)
            print("[player] keys loaded")
        except FileNotFoundError as e:
            print(f"[player] ERROR: missing key file ({e}) - run generate_keys.py first")
            return

        session_key = send_session_key(sock, house_oaep_pub)
        send_signed_hello(sock, player_id, session_key, player_signing_priv, scheme)

        nonce_tracker = protocol.NonceTracker()
        hand = receive_hand(sock, session_key, house_signing_pub, scheme, nonce_tracker)


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