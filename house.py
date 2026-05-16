import os
import socket
import threading

import config
import crypto_utils
import protocol


# player session state

class PlayerSession:
    def __init__(self, player_id, sock, addr):
        # Pre: player_id is a string, sock is a connected socket, and addr is the peer address
        # Post: creates a player session with connection details and replay tracking
        self.player_id = player_id
        self.sock = sock
        self.addr = addr
        self.session_key = None
        self.nonce_tracker = protocol.NonceTracker()


# shared game state

class GameState:
    def __init__(self):
        # Pre: none
        # Post: creates shared coordination state for both player threads
        self.barrier = threading.Barrier(config.NUM_PLAYERS)
        self.round_results = []


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
    # Pre: the house OAEP private key file exists in the keys directory
    # Post: returns the house RSA private key object
    path = os.path.join(config.KEYS_DIR, config.HOUSE_OAEP_PRIVATE_KEY)
    return crypto_utils.load_rsa_private_key(path)


def load_player_public_key(player_id, scheme):
    # Pre: player_id is a string and scheme is a valid signature scheme
    # Post: returns the player's public signing key
    filename = f"{player_id}_{scheme}_public.pem"
    path = os.path.join(config.KEYS_DIR, filename)

    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.load_rsa_public_key(path)

    return crypto_utils.load_dsa_public_key(path)


# session key exchange
def receive_session_key(session, house_oaep_priv):
    # Pre: session is connected and house_oaep_priv is the house RSA private key
    # Post: stores this player's AES session key in the session
    encrypted_key = protocol.recv_frame(session.sock)

    session_key = crypto_utils.rsa_oaep_decrypt(encrypted_key, house_oaep_priv)
    session.session_key = session_key

    print(f"[house] {session.player_id} session key received ({len(session_key)} bytes)")


# signed hello verification
def receive_signed_hello(session, player_pub, scheme):
    # Pre: session has a session key, player_pub is loaded, and scheme is valid
    # Post: returns the verified hello message dict
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


# player handler
def handle_player(session, game, house_oaep_priv, player_pub, scheme):
    # Pre: session, game, house_oaep_priv, player_pub, and scheme are valid
    # Post: handles player setup and closes the socket
    print(f"[house] {session.player_id} connected from {session.addr}")

    try:
        receive_session_key(session, house_oaep_priv)
        receive_signed_hello(session, player_pub, scheme)

    except OSError as e:
        print(f"[house] {session.player_id} socket error: {e}")

    except Exception as e:
        print(f"[house] {session.player_id} rejected: {e}")

    finally:
        session.sock.close()
        print(f"[house] {session.player_id} disconnected")


# main server
def main():
    # Pre: config contains valid server settings and key file names
    # Post: starts the house server, accepts players, and shuts down cleanly
    print("[house] Secure Internet Poker - House server")

    scheme = prompt_signature_scheme()
    print(f"[house] signature scheme: {scheme.upper()}")

    try:
        house_oaep_priv = load_house_oaep_key()

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

            session = PlayerSession(player_id, client_sock, addr)

            thread = threading.Thread(
                target=handle_player,
                args=(
                    session,
                    game,
                    house_oaep_priv,
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