import time
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa  # To generate RSA key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes  # for RSA encryption

# To store keys with key_id
# Using single dict. can occur error of using existing key for other algorithm.
# This will be fixed , by using two separate dict. for each algorithm.

aes_keys_data = {}
rsa_keys_data = {}


# For OAEP with SHA-256 padding, the maximum message length is:
#
#     2048-bit RSA: ~190 bytes
#     3072-bit RSA: ~286 bytes
#     4096-bit RSA: ~382 bytes


def generate_key_id():
    timestamp = str(int(time.time()))[-4:]  # Last 4 digits of timestamp
    random_part = secrets.token_hex(1)  # 2 random hex characters
    return f"{timestamp}{random_part}"  # Example: "6789a3" -> str output


# key_size should be in bits. ( 128 bits , 192 bits , 256 bits)
def generate_aes_key(key_size):
    byte_size = key_size // 8
    aes_key = secrets.token_bytes(byte_size)  # 256-bit AES key

    key_id = generate_key_id()
    base64_key = base64.b64encode(aes_key).decode('utf-8')  # utf is a unicode encoding method. ( one to four bytes)
    aes_keys_data.update({key_id: base64_key})

    # return {key_id: base64_key}
    return key_id, base64_key


# 2048-bit RSA Key (Recommended)
# 3072-bit RSA Key (More Secure)
# 4096-bit RSA Key (High Security)

def generate_rsa_key(key_size):
    key_id = generate_key_id()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Generate the Public Key from the Private Key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Base64 encode the PEM public key
    base64_public_key = base64.b64encode(pem_public_key).decode()

    # save as a tuple (public_key , private_key)
    rsa_keys_data.update({key_id: (private_key, public_key)})

    # return {key_id: base64_public_key}
    return key_id, base64_public_key


def encrypt_aes(key_id, plaintext):
    if key_id not in aes_keys_data:
        return "Key not found"

    base64_key = aes_keys_data[key_id]
    aes_key = base64.b64decode(base64_key)

    iv = secrets.token_bytes(16)  # Generate a new IV for each encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding (AES requires plaintext to be multiple of 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Combine IV + ciphertext and encode in base64
    iv_ciphertext_combined = iv + ciphertext

    # returning combination of iv and cipher text -> base64
    return base64.b64encode(iv_ciphertext_combined).decode()


def decrypt_aes(key_id, encoded_ciphertext):
    if key_id not in aes_keys_data:
        return "Key not found"

    base64_key = aes_keys_data[key_id]
    aes_key = base64.b64decode(base64_key)

    decoded_data = base64.b64decode(encoded_ciphertext)

    iv = decoded_data[:16]  # Extract the IV
    ciphertext = decoded_data[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decrypt_massage = cipher.decryptor()
    decrypted = decrypt_massage.update(ciphertext) + decrypt_massage.finalize()

    unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes
    plaintext = unpadder.update(decrypted) + unpadder.finalize()

    # returning plaintext - original-message
    return plaintext.decode()


def encrypt_rsa(key_id, plaintext):
    if key_id not in rsa_keys_data:
        return "Key not found"

    public_key = rsa_keys_data[key_id][1]

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #
    return base64.b64encode(ciphertext).decode()


def decrypt_rsa(key_id, ciphertext):
    if key_id not in rsa_keys_data:
        return "Key not found"

    private_key = rsa_keys_data[key_id][0]

    cipher = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')
