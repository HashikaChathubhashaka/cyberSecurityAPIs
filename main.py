from fastapi import FastAPI, HTTPException
from crypto_utils import generate_aes_key, encrypt_aes, decrypt_aes
from crypto_utils import generate_rsa_key, encrypt_rsa, decrypt_rsa
from pydantic import BaseModel
from enum import Enum
from hash_utils import sha_256_hash, sha_512_hash, sha3_224_hash, sha3_256_hash, sha3_384_hash, sha3_512_hash
from hash_utils import verify_hash
from typing import Literal

app = FastAPI()


# ---------- Crypto APIs ----------------- #

# Enum for Key Type
class KeyType(str, Enum):
    AES = "AES"
    RSA = "RSA"


# Valid key sizes for AES and RSA
VALID_AES_SIZES = {128, 192, 256}
VALID_RSA_SIZES = {2048, 3072, 4096}


# Pydantic Model for Key
class KeyRequest(BaseModel):
    key_type: KeyType
    key_size: int


class KeyResponse(BaseModel):
    key_id: str
    key_value: str


# Pydantic Model for Encryption
class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: KeyType


class EncryptResponse(BaseModel):
    ciphertext: str


# Pydantic Model for Decryption
class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: KeyType


class DecryptResponse(BaseModel):
    plaintext: str


@app.post("/generate-key", response_model=KeyResponse)
def generate_key(request: KeyRequest):
    if request.key_type == KeyType.AES:
        if request.key_size not in VALID_AES_SIZES:
            raise HTTPException(status_code=400, detail="Invalid key size. Use 128 , 192 or 256 .")
        key_id, key_value = generate_aes_key(request.key_size)
        return KeyResponse(key_id=key_id, key_value=key_value)

    elif request.key_type == KeyType.RSA:
        if request.key_size not in VALID_RSA_SIZES:
            raise HTTPException(status_code=400, detail="Invalid key size. Use 2048 , 3072 or 4096 .")
        key_id, key_value = generate_rsa_key(request.key_size)
        return KeyResponse(key_id=key_id, key_value=key_value)

    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")


# to do -> make 2 dict for AES keys and RSA keysC -ok


@app.post("/encrypt", response_model=EncryptResponse)
def encrypt(request: EncryptRequest):
    if request.algorithm == KeyType.AES:
        cipher = encrypt_aes(request.key_id, request.plaintext)
        if cipher == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given AES Key ID not found.")
        else:
            return EncryptResponse(ciphertext=cipher)

    elif request.algorithm == KeyType.RSA:
        cipher = encrypt_rsa(request.key_id, request.plaintext)
        if cipher == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given RSA Key ID not found.")
        else:
            return EncryptResponse(ciphertext=cipher)
    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")


@app.post("/decrypt", response_model=DecryptResponse)
def decrypt(request: DecryptRequest):
    if request.algorithm == KeyType.AES:
        plaintext = decrypt_aes(request.key_id, request.ciphertext)
        if plaintext == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given AES Key ID not found.")
        else:
            return DecryptResponse(plaintext=plaintext)

    elif request.algorithm == KeyType.RSA:
        plaintext = decrypt_rsa(request.key_id, request.ciphertext)
        if plaintext == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given RSA Key ID not found.")
        else:
            return DecryptResponse(plaintext=plaintext)

    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")


# ---------- Hash APIs ----------------- #

HASH_FUNCTIONS = {
    "SHA-256": sha_256_hash,
    "SHA-512": sha_512_hash,
    "SHA3-224": sha3_224_hash,
    "SHA3-256": sha3_256_hash,
    "SHA3-384": sha3_384_hash,
    "SHA3-512": sha3_512_hash,
}


class HashGeneratorRequest(BaseModel):
    data: str
    algorithm: Literal["SHA-256", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]


class HashGeneratorResponse(BaseModel):
    hash_value: str
    algorithm: str


@app.post("/generate-hash", response_model=HashGeneratorResponse)
def hash_generation(request: HashGeneratorRequest):
    hash_function = HASH_FUNCTIONS.get(request.algorithm)

    if not hash_function:
        raise HTTPException(status_code=400, detail="Unsupported algorithm. Try SHA-256 , SHA-512 , SHA3-224 , "
                                                    "SHA3-256 , SHA3-384 , SHA3-512")

    return HashGeneratorResponse(
        hash_value=hash_function(request.data),
        algorithm=request.algorithm
    )


class HashVerifierRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: Literal["SHA-256", "SHA-512", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]


class HashVerifierResponse(BaseModel):
    is_valid: bool
    message: str


@app.post("/verify-hash", response_model=HashVerifierResponse)
def hash_verification(request: HashVerifierRequest):
    hash_function = HASH_FUNCTIONS.get(request.algorithm)

    if not hash_function:
        raise HTTPException(status_code=400, detail="Unsupported algorithm. Try SHA-256 , SHA-512 , SHA3-224 , "
                                                    "SHA3-256 , SHA3-384 , SHA3-512")

    value = verify_hash(request.data, request.hash_value, hash_function)

    if value:
        return HashVerifierResponse(is_valid=True, message="Hash matches the data. ")

    else:
        return HashVerifierResponse(is_valid=False, message="Hash not matches the data.")
