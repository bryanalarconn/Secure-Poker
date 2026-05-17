# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
import os
import config
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature




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

def rsa_oaep_encrypt(plaintext, public_key):
    # Pre: plaintext is bytes and public_key is an RSA public key object
    # Post: returns RSA-OAEP encrypted ciphertext bytes
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_oaep_decrypt(ciphertext, private_key):
    # Pre: ciphertext is bytes and private_key is an RSA private key object
    # Post: returns the decrypted plaintext bytes
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def aes_cbc_encrypt(plaintext, key):
    # Pre: plaintext is bytes and key is 32 bytes
    # Post: returns IV and AES-CBC ciphertext as one bytes object
    iv = os.urandom(config.IV_SIZE)

    # Pad plaintext to a multiple of AES block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def aes_cbc_decrypt(iv_and_ciphertext, key):
    # Pre: iv_and_ciphertext contains the IV followed by ciphertext, and key is 32 bytes
    # Post: returns the decrypted plaintext bytes
    iv = iv_and_ciphertext[:config.IV_SIZE]
    ciphertext = iv_and_ciphertext[config.IV_SIZE:]

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the plaintext
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext

def rsa_pss_sign(message, private_key):
    # Pre: message is bytes and private_key is an RSA private key object
    # Post: returns RSA-PSS signature bytes
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(message, signature, public_key):
    # Pre: message is bytes, signature is bytes, and public_key is an RSA public key object
    # Post: returns True if the signature is valid, otherwise returns False
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    
def dsa_sign(message, private_key):
    # Pre: message is bytes and private_key is a DSA private key object
    # Post: returns DSA signature bytes
    return private_key.sign(message, hashes.SHA256())


def dsa_verify(message, signature, public_key):
    # Pre: message is bytes, signature is bytes, and public_key is a DSA public key object
    # Post: returns True if the signature is valid, otherwise returns False
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except InvalidSignature:
        return False