# KMS Encryption Kit

Command-line utility to encrypt Solana keypairs using AWS KMS.

## Features

- Encode Solana keypair JSON to base64
- Encrypt/decrypt using AWS KMS
- Public key verification
- Support for existing or new KMS keys

## Setup

```bash
cargo build --release
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-west-2  # Default region
```

## Usage

### Encrypt keypair:

```bash
./kms-encryption-kit <PATH_TO_KEYPAIR_JSON_FILE> <PUBLIC_KEY> [KMS_KEY_ID]
```

### Decrypt encrypted key:

```bash
./kms-encryption-kit decrypt <ENCRYPTED_BASE_64_KEY> <KMS_KEY_ID>
```

### Encrypt message:

```bash
./kms-encryption-kit encrypt-message <MESSAGE> [KMS_KEY_ID]
```

### Decrypt encrypted message:

```bash
./kms-encryption-kit decrypt-message <ENCRYPTED_BASE_64_MESSAGE> <KMS_KEY_ID>
```

### Example:

```bash
# Encrypt
./kms-encryption-kit path/to/my-keypair.json MyKeypairPublicKey1111111111111 some-secure-kms-key-id

# Decrypt
./kms-encryption-kit decrypt <ENCRYPTED_BASE_64_KEY> some-secure-kms-key-id

# Encrypt message
./kms-encryption-kit encrypt-message <message> <kms-id>

# Decrypt message
./kms-encryption-kit decrypt-message <encrypted message> <kms-id>
```

## Dependencies

See [`Cargo.toml`](./Cargo.toml) for complete list

## AWS Requirements

- KMS permissions for key creation/encryption/decryption
- Valid AWS credentials
