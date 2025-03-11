import base64
from cryptography.hazmat.primitives import hashes


def sha_256_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def sha_512_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def sha3_224_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA3_224())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def sha3_256_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def sha3_384_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA3_384())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def sha3_512_hash(message: str) -> str:
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(message.encode('utf-8'))
    return base64.b64encode(digest.finalize()).decode('utf-8')


def verify_hash(message: str, hash_value: str, hash_function) -> bool:
    return hash_function(message) == hash_value
