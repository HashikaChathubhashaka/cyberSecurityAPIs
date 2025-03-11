from fastapi import FastAPI, HTTPException
from hash_utils import sha_256_hash, sha_512_hash, sha3_224_hash, sha3_256_hash, sha3_384_hash, sha3_512_hash
from hash_utils import verify_hash
from pydantic import BaseModel
from typing import Literal

app = FastAPI()

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
