import socket
import threading

import config


# player session state
class PlayerSession:
    def __init__(self, player_id, sock, addr):
        # Pre: player_id is a string, sock is a connected socket, and addr is the peer address
        # Post: creates a player session with connection details
        self.player_id = player_id
        self.sock = sock
        self.addr = addr


# shared game state
class GameState:
    def __init__(self):
        # Pre: none
        # Post: creates shared coordination state for both player threads
        self.barrier = threading.Barrier(config.NUM_PLAYERS)
        self.round_results = []


# player handler
def handle_player(session, game):
    # Pre: session is a PlayerSession and game is the shared GameState
    # Post: handles the player connection and closes the socket
    print(f"[house] {session.player_id} connected from {session.addr}")

    try:
        session.sock.recv(config.MAX_MESSAGE_SIZE)

    except OSError as e:
        print(f"[house] {session.player_id} socket error: {e}")

    finally:
        session.sock.close()
        print(f"[house] {session.player_id} disconnected")


# main server
def main():
    # Pre: config contains valid host, port, and player count values
    # Post: starts the house server and accepts player connections
    print("[house] Secure Internet Poker - House server")

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
                args=(session, game),
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