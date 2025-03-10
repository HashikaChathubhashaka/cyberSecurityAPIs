import pytest
from crypto_utils import generate_aes_key, encrypt_aes, decrypt_aes
import base64


# Test key generation
@pytest.mark.parametrize("key_size", [128, 192, 256])
def test_generate_aes_key(key_size):
    new_aes_key_id, key = generate_aes_key(key_size)

    # Check if key is generated and has the correct length
    assert len(base64.b64decode(key)) == key_size // 8  # Convert bits to bytes
    assert isinstance(new_aes_key_id, str)  # Ensure ID is a string


# Test encryption and decryption
@pytest.mark.parametrize("key_size, plaintext", [
    (128, "I am Hashika"),
    (128, "Hello, World!"),
    (192, "Secure Encryption Test"),
    (256, "1234567890"),
    (256, "Tested for Different plaintext! 🚀")
])
def test_aes_encryption_decryption(key_size, plaintext):
    new_aes_key_id, key = generate_aes_key(key_size)
    cipher = encrypt_aes(new_aes_key_id, plaintext)
    original_message = decrypt_aes(new_aes_key_id, cipher)

    # Check if decrypted text matches original plaintext
    assert original_message == plaintext
