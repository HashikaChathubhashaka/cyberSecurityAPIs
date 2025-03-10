from fastapi import FastAPI, HTTPException
from crypto_utils import generate_aes_key, encrypt_aes, decrypt_aes
from crypto_utils import generate_rsa_key, encrypt_rsa, decrypt_rsa

app = FastAPI()


@app.post("/generate-key")
def generate_key(key_type: str, key_size: int):
    if key_type == "AES":
        if key_size == 128 or key_size == 192 or key_size == 256:
            key_id, key_value = generate_aes_key(key_size)
            return {"key_id": key_id, "key_value": key_value}
        else:
            raise HTTPException(status_code=400, detail="Invalid key size. Use 128 , 192 or 256 .")

    elif key_type == "RSA":
        if key_size == 2048 or key_size == 3072 or key_size == 4096:
            key_id, key_value = generate_rsa_key(key_size)
            return {"key_id": key_id, "key_value": key_value}
        else:
            raise HTTPException(status_code=400, detail="Invalid key size. Use 2048 , 3072 or 4096 .")

    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")


# to do -> make 2 dict for AES keys and RSA keysC
@app.post("/encrypt")
def encrypt(key_id: str, plaintext: str, algorithm: str):
    if algorithm == "AES":
        cipher = encrypt_aes(key_id, plaintext)
        if cipher == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given AES Key ID not found.")
        else:
            return {"ciphertext": cipher}

    elif algorithm == "RSA":
        cipher = encrypt_rsa(key_id, plaintext)
        if cipher == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given RSA Key ID not found.")
        else:
            return {"ciphertext": cipher}

    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")


@app.post("/decrypt")
def decrypt(key_id: str, ciphertext: str, algorithm: str):
    if algorithm == "AES":
        plaintext = decrypt_aes(key_id, ciphertext)
        if plaintext == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given AES Key ID not found.")
        else:
            return {"plaintext": plaintext}

    elif algorithm == "RSA":
        plaintext = decrypt_rsa(key_id, ciphertext)
        if plaintext == "Key not found":
            raise HTTPException(status_code=400, detail="Invalid key id. Given RSA Key ID not found.")
        else:
            return {"plaintext": plaintext}

    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")
