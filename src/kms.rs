use aws_sdk_kms::Client as KmsClient;
use base64::{engine::general_purpose::STANDARD, Engine};

pub async fn encrypt_and_store_in_kms(
    base64_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load AWS configuration from environment variables
    let config = aws_config::load_from_env().await;
    let kms_client = KmsClient::new(&config);

    // Create KMS key
    let create_key_response = kms_client
        .create_key()
        .description("Solana keypair encryption key")
        .send()
        .await?;

    let key_id = create_key_response
        .key_metadata()
        .as_ref()
        .ok_or("No key metadata")?
        .key_id();

    // Encrypt the base64 key
    let encrypt_response = kms_client
        .encrypt()
        .key_id(key_id)
        .plaintext(base64_key.as_bytes().into())
        .send()
        .await?;

    // Get the encrypted blob
    let ciphertext = encrypt_response.ciphertext_blob().unwrap();
    let ciphertext_bytes = ciphertext.as_ref();
    let encrypted_key = STANDARD.encode(ciphertext_bytes);

    println!("cypher-testblob: {:?}", ciphertext);
    Ok(encrypted_key)
}
