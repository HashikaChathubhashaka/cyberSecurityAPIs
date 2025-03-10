import pytest
from crypto_utils import generate_rsa_key, encrypt_rsa, decrypt_rsa
import base64


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_rsa_encryption_decryption(key_size):
    """Test RSA encryption and decryption for different key sizes."""
    new_rsa_key_id, pub_key = generate_rsa_key(key_size)
    plaintext = "I am Hashika"

    ciphertext = encrypt_rsa(new_rsa_key_id, plaintext)
    decrypted_message = decrypt_rsa(new_rsa_key_id, ciphertext)

    assert decrypted_message == plaintext, f"Decryption failed for {key_size}-bit RSA key"


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_rsa_with_different_messages(key_size):
    """Test RSA encryption and decryption with different plaintext messages for various key sizes."""
    new_rsa_key_id, pub_key = generate_rsa_key(key_size)

    messages = ["Hello, World!", "RSA Test", "1234567890", "!@#$%^&*()_+", "Testing long messages: " * 5]

    for msg in messages:
        ciphertext = encrypt_rsa(new_rsa_key_id, msg)
        decrypted_message = decrypt_rsa(new_rsa_key_id, ciphertext)

        assert decrypted_message == msg, f"Failed for message: {msg} with {key_size}-bit RSA key"


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_tampered_ciphertext(key_size):
    """Test that modifying the ciphertext results in a decryption failure for various key sizes."""
    new_rsa_key_id, pub_key = generate_rsa_key(key_size)
    plaintext = "I am Hashika"

    ciphertext = encrypt_rsa(new_rsa_key_id, plaintext)

    # Tamper with the ciphertext (e.g., modify a character)
    tampered_ciphertext = base64.b64encode(base64.b64decode(ciphertext)[:-1] + b'\x00').decode()

    with pytest.raises(Exception):  # Expect an error during decryption
        decrypt_rsa(new_rsa_key_id, tampered_ciphertext)
