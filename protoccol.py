import json
import time
import struct
import secrets
import config
import crypto_utils


# message serialization
def serialize(message_dict):
    # Pre: message_dict is a JSON-serializable dict
    # Post: returns deterministic UTF-8 JSON bytes
    return json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize(message_bytes):
    # Pre: message_bytes is UTF-8 JSON bytes
    # Post: returns the decoded message dict
    return json.loads(message_bytes.decode("utf-8"))

# message construction
def build_message(msg_type, sender, payload):
    # Pre: msg_type and sender are strings, and payload is a JSON-serializable dict
    # Post: returns a message dict with type, nonce, timestamp, sender, and payload
    return {
        "type": msg_type,
        "nonce": secrets.token_bytes(config.NONCE_SIZE).hex(),
        "timestamp": int(time.time()),
        "sender": sender,
        "payload": payload,
    }

# tcp framing
def send_frame(sock, payload_bytes):
    # Pre: sock is a connected socket and payload_bytes is bytes
    # Post: sends a length-prefixed payload over the socket
    if len(payload_bytes) > config.MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {len(payload_bytes)} bytes")

    length_prefix = struct.pack(">I", len(payload_bytes))
    sock.sendall(length_prefix + payload_bytes)

def recv_frame(sock):
    # Pre: sock is a connected socket
    # Post: returns one complete payload from the socket
    length_bytes = _recv_exact(sock, config.LENGTH_PREFIX_SIZE)
    (length,) = struct.unpack(">I", length_bytes)

    if length > config.MAX_MESSAGE_SIZE:
        raise ValueError(f"incoming frame too large: {length} bytes")

    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    # Pre: sock is a connected socket and n is the number of bytes to read
    # Post: returns exactly n bytes, or raises an error if the connection closes
    buf = bytearray()

    while len(buf) < n:
        chunk = sock.recv(n - len(buf))

        if not chunk:
            raise ConnectionError("connection closed mid-frame")

        buf.extend(chunk)

    return bytes(buf)


# anti-replay tracking
class NonceTracker:
    def __init__(self):
        # Pre: none
        # Post: creates an empty nonce tracker
        self._seen = set()

    def check_and_record(self, nonce_hex, timestamp):
        # Pre: nonce_hex is a string and timestamp is a Unix timestamp
        # Post: returns True if the message is fresh and the nonce has not been used
        now = int(time.time())

        if abs(now - timestamp) > config.TIMESTAMP_TOLERANCE_SECONDS:
            return False

        if nonce_hex in self._seen:
            return False

        self._seen.add(nonce_hex)
        return True


# signature helpers
def sign(message_bytes, private_key, scheme):
    # Pre: message_bytes is bytes, private_key matches the scheme, and scheme is valid
    # Post: returns signature bytes
    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.rsa_pss_sign(message_bytes, private_key)

    if scheme == config.SIG_SCHEME_DSA:
        return crypto_utils.dsa_sign(message_bytes, private_key)

    raise ValueError(f"unknown signature scheme: {scheme}")


def verify(message_bytes, signature, public_key, scheme):
    # Pre: message_bytes and signature are bytes, public_key matches the scheme
    # Post: returns True if the signature is valid, otherwise returns False
    if scheme == config.SIG_SCHEME_RSA:
        return crypto_utils.rsa_pss_verify(message_bytes, signature, public_key)

    if scheme == config.SIG_SCHEME_DSA:
        return crypto_utils.dsa_verify(message_bytes, signature, public_key)

    raise ValueError(f"unknown signature scheme: {scheme}")


# message types
MSG_SESSION_KEY = "session_key"
MSG_HAND = "hand"
MSG_MOVE = "move"
MSG_ROUND_RESULT = "round_result"
MSG_WINNER = "winner"