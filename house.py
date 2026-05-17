import os
import socket
import threading

import config
import crypto_utils
import game_logic
import protocol


# player session state
class PlayerSession:
    def __init__(self, player_id, sock, addr):
        # Pre: player_id is valid, sock is connected, and addr is the peer address
        # Post: creates a session for one player
        self.player_id = player_id
        self.sock = sock
        self.addr = addr
        self.session_key = None
        self.nonce_tracker = protocol.NonceTracker()
        self.hand = None
        self.played_cards = set()
        self.current_move = None


# shared game state
class GameState:
    def __init__(self):
        # Pre: none
        # Post: creates shared state for both player threads
        self.barrier = threading.Barrier(config.NUM_PLAYERS)
        self.round_results = []
        self.winner = None
        self.p1_session = None
        self.p2_session = None


# signature scheme selection
def prompt_signature_scheme():
    # Pre: none
    # Post: returns the selected signature scheme
    print("[house] Select signature scheme for this game:")
    print("  1 - RSA (PSS)")
    print("  2 - DSA")

    while True:
        choice = input("[house] enter 1 or 2: ").strip()

        if choice == "1":
            return config.SIG_SCHEME_RSA

        if choice == "2":
            return config.SIG_SCHEME_DSA

        print("[house] invalid choice - enter 1 or 2")


# key loading
def load_house_oaep_key():
    # Pre: the house OAEP private key exists
    # Post: returns the house RSA private key
    path = os.path.join(config.KEYS_DIR, config.HOUSE_OAEP_PRIVATE_KEY)
    return crypto_utils.load_rsa_private_key(path)


def load_house_signing_key(scheme):
    # Pre: scheme is valid and the matching house signing key exists
    # Post: returns the house private signing key
    filename = f"house_{scheme}_private.pem"
    path = os.path.join(config.KEYS_DIR, filename)

    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.load_rsa_private_key(path)

    return crypto_utils.load_dsa_private_key(path)

def load_player_public_key(player_id, scheme):
    # Pre: player_id and scheme are valid
    # Post: returns the player's public signing key
    filename = f"{player_id}_{scheme}_public.pem"
    path = os.path.join(config.KEYS_DIR, filename)

    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.load_rsa_public_key(path)

    return crypto_utils.load_dsa_public_key(path)


# signed message sending
def send_signed_message(sock, msg_type, payload, session_key, house_signing_priv, scheme):
    # Pre: socket, session key, signing key, and scheme are valid
    # Post: sends a signed and encrypted message
    msg = protocol.build_message(msg_type, "house", payload)
    msg_bytes = protocol.serialize(msg)

    signature = protocol.sign(msg_bytes, house_signing_priv, scheme)
    bundle = msg_bytes + b"||" + signature

    ciphertext = crypto_utils.aes_cbc_encrypt(bundle, session_key)
    protocol.send_frame(sock, ciphertext)


# session key exchange
def receive_session_key(session, house_oaep_priv):
    # Pre: session socket is connected and the house OAEP key is loaded
    # Post: stores this player's AES session key
    encrypted_key = protocol.recv_frame(session.sock)

    session_key = crypto_utils.rsa_oaep_decrypt(encrypted_key, house_oaep_priv)
    session.session_key = session_key

    print(f"[house] {session.player_id} session key received ({len(session_key)} bytes)")


# signed hello verification
def receive_signed_hello(session, player_pub, scheme):
    # Pre: session key is set and the player's public key is loaded
    # Post: returns the verified hello message
    ciphertext = protocol.recv_frame(session.sock)

    bundle = crypto_utils.aes_cbc_decrypt(ciphertext, session.session_key)
    msg_bytes, signature = bundle.split(b"||", 1)

    if not protocol.verify(msg_bytes, signature, player_pub, scheme):
        raise ValueError("signature verification failed")

    msg = protocol.deserialize(msg_bytes)

    if not session.nonce_tracker.check_and_record(msg["nonce"], msg["timestamp"]):
        raise ValueError("replay or stale message rejected")

    print(f"[house] {session.player_id} signed hello verified")
    return msg

# hand distribution
def deal_and_send_hand(session, house_signing_priv, scheme):
    # Pre: session key is set and the house signing key is loaded
    # Post: stores and sends this player's hand
    hand = game_logic.deal_hand()
    session.hand = hand

    send_signed_message(
        session.sock,
        protocol.MSG_HAND,
        {"cards": hand},
        session.session_key,
        house_signing_priv,
        scheme,
    )

    print(f"[house] {session.player_id} dealt hand: {hand}")


# move receiving
def receive_move(session, player_pub, scheme, round_num):
    # Pre: player is set up and has a hand
    # Post: stores the player's valid move
    ciphertext = protocol.recv_frame(session.sock)

    bundle = crypto_utils.aes_cbc_decrypt(ciphertext, session.session_key)
    msg_bytes, signature = bundle.split(b"||", 1)

    if not protocol.verify(msg_bytes, signature, player_pub, scheme):
        raise ValueError("move signature verification failed")

    msg = protocol.deserialize(msg_bytes)

    if not session.nonce_tracker.check_and_record(msg["nonce"], msg["timestamp"]):
        raise ValueError("replay or stale move rejected")

    card = msg["payload"]["card"]

    # Signature checks who sent it, then the hand check makes sure it is legal
    if not game_logic.validate_choice(card, session.hand):
        raise ValueError(f"illegal move: {card} not in hand {session.hand}")

    # Prevent the same valid card from being reused in another round
    if card in session.played_cards:
        raise ValueError(f"illegal move: {card} already played this game")

    session.played_cards.add(card)
    session.current_move = card
    print(f"[house] {session.player_id} played {card} (round {round_num})")


# round play
def play_round(session, game, player_pub, house_signing_priv, scheme, round_num):
    # Pre: session is fully set up, game is shared, and round_num is valid
    # Post: receives the player's move, compares the round, and sends the result
    receive_move(session, player_pub, scheme, round_num)

    # Wait until both players have submitted a move
    game.barrier.wait()

    is_leader = session.player_id == "player1"

    if is_leader:
        p1_move = game.p1_session.current_move
        p2_move = game.p2_session.current_move

        result = game_logic.compare_round(p1_move, p2_move)
        game.round_results.append(result)

        print(f"[house] round {round_num} result: P1={p1_move} P2={p2_move} -> {result}")

    # Wait until the leader has written the result
    game.barrier.wait()

    result = game.round_results[round_num - 1]

    send_signed_message(
        session.sock,
        protocol.MSG_ROUND_RESULT,
        {"round": round_num, "result": result},
        session.session_key,
        house_signing_priv,
        scheme,
    )

# winner announcement
def announce_winner(session, game, house_signing_priv, scheme):
    # Pre: all round results are stored
    # Post: sends the final winner message
    is_leader = session.player_id == "player1"

    if is_leader:
        game.winner = game_logic.determine_winner(game.round_results)
        print(f"[house] game over - results {game.round_results} -> winner: {game.winner}")

    # Make sure the winner is set before either thread sends it
    game.barrier.wait()

    send_signed_message(
        session.sock,
        protocol.MSG_WINNER,
        {"winner": game.winner, "results": game.round_results},
        session.session_key,
        house_signing_priv,
        scheme,
    )


# session key cleanup
def destroy_session_key(session):
    # Pre: session may or may not have a session key
    # Post: clears the session key reference
    if session.session_key is None:
        return

    session.session_key = b"\x00" * config.AES_KEY_SIZE
    session.session_key = None

    print(f"[house] {session.player_id} session key destroyed")
# player handler
def handle_player(session, game, house_oaep_priv, house_signing_priv, player_pub, scheme):
    # Pre: all keys and session values are valid
    # Post: handles the full player session and closes the socket
    print(f"[house] {session.player_id} connected from {session.addr}")

    try:
        receive_session_key(session, house_oaep_priv)
        receive_signed_hello(session, player_pub, scheme)
        deal_and_send_hand(session, house_signing_priv, scheme)

        for round_num in range(1, game_logic.NUM_ROUNDS + 1):
            play_round(
                session,
                game,
                player_pub,
                house_signing_priv,
                scheme,
                round_num,
            )

        announce_winner(session, game, house_signing_priv, scheme)

    except threading.BrokenBarrierError:
        print(f"[house] {session.player_id} aborted: other player failed")

    except OSError as e:
        print(f"[house] {session.player_id} socket error: {e}")

    except Exception as e:
        print(f"[house] {session.player_id} rejected: {e}")
        game.barrier.abort()

    finally:
        destroy_session_key(session)
        session.sock.close()
        print(f"[house] {session.player_id} disconnected")


# main server
def main():
    # Pre: config contains valid server settings and key file names
    # Post: starts the house server, runs the game, and shuts down cleanly
    print("[house] Secure Internet Poker - House server")

    scheme = prompt_signature_scheme()
    print(f"[house] signature scheme: {scheme.upper()}")

    try:
        house_oaep_priv = load_house_oaep_key()
        house_signing_priv = load_house_signing_key(scheme)

        player_pubs = {
            "player1": load_player_public_key("player1", scheme),
            "player2": load_player_public_key("player2", scheme),
        }

        print("[house] keys loaded")

    except FileNotFoundError as e:
        print(f"[house] ERROR: missing key file ({e}) - run generate_keys.py first")
        return

    game = GameState()
    threads = []

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((config.HOST, config.PORT))
        server_sock.listen(config.NUM_PLAYERS)

        print(f"[house] listening on {config.HOST}:{config.PORT}")
        print(f"[house] waiting for {config.NUM_PLAYERS} players...")

        for i in range(config.NUM_PLAYERS):
            client_sock, addr = server_sock.accept()
            player_id = f"player{i + 1}"
            # Tell the player which identity/key pair it should use.
            protocol.send_frame(client_sock, player_id.encode("utf-8"))

            session = PlayerSession(player_id, client_sock, addr)

            if player_id == "player1":
                game.p1_session = session
            else:
                game.p2_session = session

            thread = threading.Thread(
                target=handle_player,
                args=(
                    session,
                    game,
                    house_oaep_priv,
                    house_signing_priv,
                    player_pubs[player_id],
                    scheme,
                ),
                name=f"{player_id}-thread",
            )

            thread.start()
            threads.append(thread)

        print(f"[house] {config.NUM_PLAYERS} players connected")

        for thread in threads:
            thread.join()

    except OSError as e:
        print(f"[house] server socket error: {e}")

    finally:
        server_sock.close()
        print("[house] server socket closed - shutdown complete")


if __name__ == "__main__":
    main()