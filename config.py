# network settings
HOST = "127.0.0.1"
PORT = 50007
LENGTH_PREFIX_SIZE = 4
MAX_MESSAGE_SIZE = 65536

# game settings
NUM_PLAYERS = 2


# rsa settings
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


# dsa settings
DSA_KEY_SIZE = 2048


# aes settings
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
IV_SIZE = 16


# hash settings
HASH_ALGORITHM_NAME = "SHA-256"


# anti-replay settings
NONCE_SIZE = 16
TIMESTAMP_TOLERANCE_SECONDS = 60


# signature scheme options
SIG_SCHEME_RSA = "rsa"
SIG_SCHEME_DSA = "dsa"
VALID_SIG_SCHEMES = (SIG_SCHEME_RSA, SIG_SCHEME_DSA)


# file paths
KEYS_DIR = "keys"
HOUSE_OAEP_PRIVATE_KEY = "house_oaep_private.pem"
HOUSE_OAEP_PUBLIC_KEY = "house_oaep_public.pem"

# player key files use this pattern:
# player{N}_{scheme}_{private|public}.pem
# example: player1_rsa_private.pem