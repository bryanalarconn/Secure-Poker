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
        # Pre: player_id is a string, sock is a connected socket, and addr is the peer address
        # Post: creates a player session with connection details, replay tracking, and hand storage
        self.player_id = player_id
        self.sock = sock
        self.addr = addr
        self.session_key = None
        self.nonce_tracker = protocol.NonceTracker()
        self.hand = None


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


def load_house_signing_key(scheme):
    # Pre: scheme is a valid signature scheme and the house signing key file exists
    # Post: returns the house private signing key object
    filename = f"house_{scheme}_private.pem"
    path = os.path.join(config.KEYS_DIR, filename)

    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.load_rsa_private_key(path)

    return crypto_utils.load_dsa_private_key(path)


def load_player_public_key(player_id, scheme):
    # Pre: player_id is a string and scheme is a valid signature scheme
    # Post: returns the player's public signing key
    filename = f"{player_id}_{scheme}_public.pem"
    path = os.path.join(config.KEYS_DIR, filename)

    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.load_rsa_public_key(path)

    return crypto_utils.load_dsa_public_key(path)


# signed message sending
def send_signed_message(sock, msg_type, payload, session_key, house_signing_priv, scheme):
    # Pre: sock is connected, session_key is bytes, house_signing_priv is loaded, and scheme is valid
    # Post: sends a signed and encrypted message over the socket
    msg = protocol.build_message(msg_type, "house", payload)
    msg_bytes = protocol.serialize(msg)

    signature = protocol.sign(msg_bytes, house_signing_priv, scheme)
    bundle = msg_bytes + b"||" + signature

    ciphertext = crypto_utils.aes_cbc_encrypt(bundle, session_key)
    protocol.send_frame(sock, ciphertext)


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

# hand distribution
def deal_and_send_hand(session, house_signing_priv, scheme):
    # Pre: session has a session key, house_signing_priv is loaded, and scheme is valid
    # Post: stores this player's hand and sends it as a signed encrypted message
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


# player handler
def handle_player(session, game, house_oaep_priv, house_signing_priv, player_pub, scheme):
    # Pre: session, game, house_oaep_priv, house_signing_priv, player_pub, and scheme are valid
    # Post: handles player setup, sends the player's hand, and closes the socket
    print(f"[house] {session.player_id} connected from {session.addr}")

    try:
        receive_session_key(session, house_oaep_priv)
        receive_signed_hello(session, player_pub, scheme)
        deal_and_send_hand(session, house_signing_priv, scheme)

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

            session = PlayerSession(player_id, client_sock, addr)

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