use base64::{engine::general_purpose::STANDARD, Engine};
use kms::{decrypt_with_kms, encrypt_and_store_in_kms};
use serde_json::Value;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signer::Signer;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

mod kms;

fn read_keypair_from_json<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Read the JSON file
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON and extract bytes
    let json: Value = serde_json::from_str(&contents)?;

    // Handle both array format and object format
    let bytes = if json.is_array() {
        // Direct array of numbers
        json.as_array()
            .ok_or("Invalid JSON format")?
            .iter()
            .map(|v| v.as_u64().ok_or("Invalid number in array"))
            .collect::<Result<Vec<u64>, _>>()?
            .iter()
            .map(|&v| v as u8)
            .collect()
    } else {
        // Check if it's in the [0, 0, 0, ...] string format
        match json.get("private_key") {
            Some(pk) => {
                // Remove brackets and split by commas
                let pk_str = pk.as_str().ok_or("Invalid private key format")?;
                let cleaned = pk_str
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(|s| s.trim().parse::<u8>())
                    .collect::<Result<Vec<u8>, _>>()?;
                cleaned
            }
            None => return Err("Could not find private key in JSON".into()),
        }
    };

    Ok(bytes)
}
fn encode_key_to_base64(key: &[u8]) -> String {
    STANDARD.encode(key)
}

fn verify_and_encode_key(
    private_key_bytes: &[u8],
    expected_pubkey: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Create keypair from private key bytes
    let keypair = if private_key_bytes.len() == 32 {
        // If we only have the secret key, extend it to full keypair
        let secret = ed25519_dalek::SecretKey::try_from(private_key_bytes)?;
        let public = ed25519_dalek::SigningKey::from_bytes(&secret);
        let mut full_keypair = Vec::with_capacity(64);
        full_keypair.extend_from_slice(private_key_bytes);
        full_keypair.extend_from_slice(public.as_bytes());
        Keypair::from_bytes(&full_keypair)?
    } else {
        Keypair::from_bytes(private_key_bytes)?
    };

    let derived_pubkey = keypair.pubkey();
    let expected_pubkey = Pubkey::from_str(expected_pubkey)?;

    if derived_pubkey != expected_pubkey {
        return Err("Derived public key does not match expected public key".into());
    }

    // Return just the private key portion encoded in base64
    Ok(encode_key_to_base64(&keypair.to_bytes()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let usage = format!(
        "Usage:\n\
        {} <path-to-private-key> <expected-public-key> [kms-key-id]\n\
        {} --decode\n\
        {} decrypt <encrypted-key> <kms-key-id>",
        args[0], args[0], args[0]
    );

    if args.len() < 2 {
        eprintln!("{}", usage);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "decrypt" => {
            if args.len() != 4 {
                eprintln!("Usage: {} decrypt <encrypted-key> <kms-key-id>", args[0]);
                std::process::exit(1);
            }
            let encrypted_key = &args[2];
            let key_id = &args[3];
            let decrypted_bytes = decrypt_with_kms(encrypted_key, key_id).await?;
            let base64_key = String::from_utf8(decrypted_bytes)?;
            let keypair_bytes = STANDARD.decode(base64_key)?;
            let keypair = Keypair::from_bytes(&keypair_bytes)?;
            println!("Decrypted public key: {}", keypair.pubkey());
            println!("Decrypted secret key: {:?}", keypair.to_base58_string());
        } // ... rest of the match cases remain the same
        _ => {
            let usage = format!(
                "Usage: {} <path-to-private-key> <expected-public-key> [kms-key-id]",
                args[0]
            );

            if args.len() < 3 || args.len() > 4 {
                eprintln!("{}", usage);
                std::process::exit(1);
            }

            let key_path = &args[1];
            let expected_pubkey = &args[2];
            let kms_key_id = args.get(3);

            match read_keypair_from_json(key_path) {
                Ok(private_key) => match verify_and_encode_key(&private_key, expected_pubkey) {
                    Ok(encoded) => {
                        println!("Public key verified successfully!");
                        let encrypted =
                            encrypt_and_store_in_kms(&encoded, kms_key_id.map(|s| s.as_str()))
                                .await?;
                        println!("Encrypted key: {}", encrypted);
                        if kms_key_id.is_none() {
                            println!("New KMS key created");
                        }
                    }
                    Err(e) => {
                        eprintln!("Error verifying key: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("Error reading private key file: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_verify_and_encode_key() -> Result<(), Box<dyn std::error::Error>> {
        // Create a known keypair for testing
        let keypair = Keypair::new();
        let pubkey = keypair.pubkey().to_string();

        // Create JSON file with keypair
        let json = serde_json::to_string(&keypair.to_bytes().to_vec())?;

        let temp_file = NamedTempFile::new()?;
        write(temp_file.path(), json)?;

        // Read and verify the key
        let read_key = read_keypair_from_json(temp_file.path())?;
        let encoded = verify_and_encode_key(&read_key, &pubkey)?;

        assert!(!encoded.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_and_encode_decode_key() -> Result<(), Box<dyn std::error::Error>> {
        // Create a known keypair for testing
        let keypair = Keypair::new();
        let pubkey = keypair.pubkey().to_string();
        println!("origin pubkey: {}", pubkey.to_string());
        println!("origin private pubkey: {}", keypair.to_base58_string());
        // Create JSON file with keypair
        let json = serde_json::to_string(&keypair.to_bytes().to_vec())?;

        let temp_file = NamedTempFile::new()?;
        write(temp_file.path(), json)?;

        // Read and verify the key
        let read_key = read_keypair_from_json(temp_file.path())?;
        let utf8_string = verify_and_encode_key(&read_key, &pubkey)?;

        assert!(!utf8_string.is_empty());

        let key_id = "2d20909e-02f9-41b0-8fbc-2e4dc37b2915";

        let encrypted_kms_data = encrypt_and_store_in_kms(&utf8_string, Some(key_id)).await?;
        // let encrypted_kms_data = String::from_utf8(encrypted_kms_data);

        let decrypted_bytes = decrypt_with_kms(encrypted_kms_data.as_str(), key_id).await?;
        let base64_key = String::from_utf8(decrypted_bytes)?;
        // let keypair_bytes = decode_from_base64(&base64_key)?;
        let keypair_bytes = STANDARD.decode(base64_key)?;
        let keypair = Keypair::from_bytes(&keypair_bytes)?;
        println!("Decrypted public key: {}", keypair.pubkey());
        println!("Decrypted private key: {:?}", keypair.to_base58_string());

        Ok(())
    }
}
