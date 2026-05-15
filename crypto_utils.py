# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
from cryptography.hazmat.primitives import serialization


def load_rsa_private_key(path):
    # Pre:  path points to a PEM-encoded RSA private key written by generate_keys.py
    # Post: returns an RSAPrivateKey object usable for OAEP decryption or PSS signing
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return serialization.load_pem_private_key(pem_bytes, password=None)


def load_rsa_public_key(path):
    # Pre:  path points to a PEM-encoded RSA public key
    # Post: returns an RSAPublicKey object usable for OAEP encryption or PSS verification
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return serialization.load_pem_public_key(pem_bytes)


def load_dsa_private_key(path):
    # Pre:  path points to a PEM-encoded DSA private key written by generate_keys.py
    # Post: returns a DSAPrivateKey object usable for DSA signing
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return serialization.load_pem_private_key(pem_bytes, password=None)


def load_dsa_public_key(path):
    # Pre:  path points to a PEM-encoded DSA public key
    # Post: returns a DSAPublicKey object usable for DSA signature verification
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return serialization.load_pem_public_key(pem_bytes)