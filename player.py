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


# session key cleanup
def destroy_session_key(session_key):
    # Pre: session_key is bytes or None
    # Post: clears the session key reference
    if session_key is None:
        return

    session_key = b"\x00" * config.AES_KEY_SIZE
    del session_key

    print("[player] session key destroyed")


# main client
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

        try:
            house_oaep_pub, player_signing_priv, house_signing_pub = load_keys(
                player_id,
                scheme,
            )

            print("[player] keys loaded")

        except FileNotFoundError as e:
            print(f"[player] ERROR: missing key file ({e}) - run generate_keys.py first")
            return


    except OSError as e:
        print(f"[player] connection error: {e}")

    finally:
        destroy_session_key(session_key)
        sock.close()
        print("[player] disconnected")


if __name__ == "__main__":
    main()