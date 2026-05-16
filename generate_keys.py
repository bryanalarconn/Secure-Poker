import os
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization
import config   # single source of truth for key sizes, paths


def ensure_keys_dir():
    # Pre:  none
    # Post: the keys/ directory exists (no-op if it already did)
    os.makedirs(config.KEYS_DIR, exist_ok=True)


def write_private_key(private_key, filename):
    # Pre:  private_key is an RSA or DSA private key object; filename is a basename
    # Post: the key is written PEM-encoded (PKCS8, no passphrase) into keys/
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,          # works for both RSA and DSA
        encryption_algorithm=serialization.NoEncryption(),  # no passphrase (class project)
    )
    path = os.path.join(config.KEYS_DIR, filename)
    with open(path, "wb") as f:   # wb = write binary, PEM is bytes
        f.write(pem_bytes)
    print(f"  wrote {path}")


def write_public_key(public_key, filename):
    # Pre:  public_key is an RSA or DSA public key object; filename is a basename
    # Post: the key is written PEM-encoded (SubjectPublicKeyInfo) into keys/
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,   # standard for public keys
    )
    path = os.path.join(config.KEYS_DIR, filename)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    print(f"  wrote {path}")


def generate_rsa_keypair(name_prefix):
    # Pre:  name_prefix is a basename stem (e.g. "house_oaep", "player1_rsa")
    # Post: writes {name_prefix}_private.pem and {name_prefix}_public.pem into keys/
    private_key = rsa.generate_private_key(
        public_exponent=config.RSA_PUBLIC_EXPONENT,
        key_size=config.RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()   # derived from private, not generated separately

    write_private_key(private_key, f"{name_prefix}_private.pem")
    write_public_key(public_key, f"{name_prefix}_public.pem")


def generate_dsa_keypair(name_prefix):
    # Pre:  name_prefix is a basename stem (e.g. "house_dsa", "player1_dsa")
    # Post: writes {name_prefix}_private.pem and {name_prefix}_public.pem into keys/
    # DSA is two-step unlike RSA: group params (p,q,g) first, then private key x within that group
    parameters = dsa.generate_parameters(key_size=config.DSA_KEY_SIZE)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    write_private_key(private_key, f"{name_prefix}_private.pem")
    write_public_key(public_key, f"{name_prefix}_public.pem")


def main():
    print("Generating keys for Secure Internet Poker...")
    ensure_keys_dir()
    print("\nHouse OAEP keypair (RSA-2048, session key exchange):")
    generate_rsa_keypair("house_oaep")

    # House signing keys for authenticity of House messages (hand, results, winner).
    print("\nHouse signing keys (RSA + DSA):")
    generate_rsa_keypair("house_rsa")
    generate_dsa_keypair("house_dsa")

    print("\nPlayer 1 signing keys (RSA + DSA):")
    generate_rsa_keypair("player1_rsa")
    generate_dsa_keypair("player1_dsa")

    print("\nPlayer 2 signing keys (RSA + DSA):")
    generate_rsa_keypair("player2_rsa")
    generate_dsa_keypair("player2_dsa")
    
    print("\nDone. All keys written to keys/")


if __name__ == "__main__":   # only runs when executed directly, not when imported
    main()