import pytest
from hash_utils import (  # Replace 'your_module' with your actual Python file name
    sha_256_hash, sha_512_hash,
    sha3_224_hash, sha3_256_hash, sha3_384_hash, sha3_512_hash,
    verify_hash
)


@pytest.mark.parametrize("hash_function", [
    sha_256_hash,
    sha_512_hash,
    sha3_224_hash,
    sha3_256_hash,
    sha3_384_hash,
    sha3_512_hash
])
def test_hash_functions(hash_function):
    message = "Test Message"
    hashed_value = hash_function(message)
    assert isinstance(hashed_value, str)  # Check if output is a string
    assert verify_hash(message, hashed_value, hash_function)  # Check if hash verification works


def test_verify_hash_failure():
    message = "Test Message"
    wrong_message = "Wrong Message"
    hashed_value = sha_256_hash(message)

    assert not verify_hash(wrong_message, hashed_value, sha_256_hash)  # Should return False
