# Solana Key Encoder/Decoder

A command-line utility for encoding Solana keypairs to base64 and decoding base64 strings back to keypairs.

## Features

- Encode Solana keypair JSON files to base64
- Decode base64 strings back to keypairs
- Verify public key matches during encoding
- Support for different JSON keypair formats

## Installation

```bash
cargo build --release
```

## Usage

### Encoding

```bash
./target/release/kms-encryption-kit <path-to-keypair.json> <public-key>
```

### Decoding

```bash
./target/release/kms-encryption-kit --decode
```

## Dependencies

```toml
base64 = "0.21"
ed25519-dalek = "2.0"
solana-sdk = "1.17"
serde_json = "1.0"
```

## License

MIT
