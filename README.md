# Cyber Security API

A simple API for cryptographic operations including key generation, encryption, decryption, hashing, and hash verification.

## API Endpoints

### Key Generation
- **Generate Key**  
  `POST https://cyber-security-api.vercel.app/generate-key`
  - Supports AES (128, 192, 256-bit) and RSA (2048, 3072, 4096-bit) keys.

### Encryption & Decryption
- **Encrypt Data**  
  `POST https://cyber-security-api.vercel.app/encrypt`
  - Encrypts data using the provided key.

- **Decrypt Data**  
  `POST https://cyber-security-api.vercel.app/decrypt`
  - Decrypts the encrypted data.

### Hashing & Verification
- **Generate Hash**  
  `POST https://cyber-security-api.vercel.app/generate-hash`
  - Creates a hash from the given input.

- **Verify Hash**  
  `POST https://cyber-security-api.vercel.app/verify-hash`
  - Checks if a given hash matches the input data.

## Supported Key Types

| Algorithm | Key Sizes |
|-----------|----------|
| AES       | 128, 192, 256 bits |
| RSA       | 2048, 3072, 4096 bits |

## Supported Hash Functions

- SHA-256
- SHA-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512

## Documentation
Full API documentation can be found [here](https://cyber-security-api.vercel.app/docs#/).

## Installation & Usage

Clone the repository:
```bash
git clone https://github.com/yourusername/cyber-security-api.git
cd cyber-security-api
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the API:
```bash
python app.py
```

