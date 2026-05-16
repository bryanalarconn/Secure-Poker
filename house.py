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
        # Post: creates a player session with connection details
        self.player_id = player_id
        self.sock = sock
        self.addr = addr
        self.session_key = None


# shared game state
class GameState:
    def __init__(self):
        # Pre: none
        # Post: creates shared coordination state for both player threads
        self.barrier = threading.Barrier(config.NUM_PLAYERS)
        self.round_results = []

# key loading
def load_house_oaep_key():
    # Pre: the house OAEP private key file exists in the keys directory
    # Post: returns the house RSA private key object
    path = os.path.join(config.KEYS_DIR, config.HOUSE_OAEP_PRIVATE_KEY)
    return crypto_utils.load_rsa_private_key(path)

# session key exchange
def receive_session_key(session, house_oaep_priv):
    # Pre: session is connected and house_oaep_priv is the house RSA private key
    # Post: stores this player's AES session key in the session
    encrypted_key = protocol.recv_frame(session.sock)

    session_key = crypto_utils.rsa_oaep_decrypt(encrypted_key, house_oaep_priv)
    session.session_key = session_key

    print(f"[house] {session.player_id} session key received ({len(session_key)} bytes)")


# player handler

def handle_player(session, game, house_oaep_priv):
    # Pre: session is a PlayerSession, game is the shared GameState, and house_oaep_priv is loaded
    # Post: handles the player's session key setup and closes the socket
    print(f"[house] {session.player_id} connected from {session.addr}")

    try:
        receive_session_key(session, house_oaep_priv)

    except (OSError, ConnectionError, ValueError) as e:
        print(f"[house] {session.player_id} error during session setup: {e}")

    finally:
        session.sock.close()
        print(f"[house] {session.player_id} disconnected")


# main server

def main():
    # Pre: config contains valid server settings and key file names
    # Post: starts the house server, accepts players, and shuts down cleanly
    print("[house] Secure Internet Poker - House server")

    house_oaep_priv = load_house_oaep_key()
    print("[house] OAEP private key loaded")

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
                args=(session, game, house_oaep_priv),
                name=f"{player_id}-thread",
            )

            thread.start()
            threads.append(thread)

        print(f"[house] {config.NUM_PLAYERS} players connected - game would start here")

        for thread in threads:
            thread.join()

    except OSError as e:
        print(f"[house] server socket error: {e}")

    finally:
        server_sock.close()
        print("[house] server socket closed - shutdown complete")


if __name__ == "__main__":
    main()