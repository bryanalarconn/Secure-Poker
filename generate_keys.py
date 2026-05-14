import os
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "keys"
RSA_KEY_SIZE = 2048   # smallest RSA size still secure in 2026
DSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537   # F4, universal default


def ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)   # no-op if already exists


def write_private_key(private_key, filename):
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,         # works for RSA and DSA
        encryption_algorithm=serialization.NoEncryption(), # no passphrase (class project)
    )
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "wb") as f:   # wb = write binary, PEM is bytes
        f.write(pem_bytes)
    print(f"  wrote {path}")


def write_public_key(public_key, filename):
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,   # standard for public keys
    )
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    print(f"  wrote {path}")


def generate_rsa_keypair(name_prefix):
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    public_key = private_key.public_key()   # derived from private, not generated separately
    
    write_private_key(private_key, f"{name_prefix}_private.pem")
    write_public_key(public_key, f"{name_prefix}_public.pem")


def generate_dsa_keypair(name_prefix):
    # DSA is two-step unlike RSA: group params (p,q,g) first, then private key x within that group
    parameters = dsa.generate_parameters(key_size=DSA_KEY_SIZE)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    write_private_key(private_key, f"{name_prefix}_private.pem")
    write_public_key(public_key, f"{name_prefix}_public.pem")


def main():
    print("Generating keys for Secure Internet Poker...")
    ensure_keys_dir()
    
    print("\nHouse keypair (RSA-2048, for OAEP):")
    generate_rsa_keypair("house")
    
    print("\nPlayer 1 signing keys:")
    generate_rsa_keypair("player1_rsa")
    generate_dsa_keypair("player1_dsa")
    
    print("\nPlayer 2 signing keys:")
    generate_rsa_keypair("player2_rsa")
    generate_dsa_keypair("player2_dsa")
    
    print("\nDone. All keys written to keys/")


if __name__ == "__main__":   # only runs when executed directly, not when imported
    main()