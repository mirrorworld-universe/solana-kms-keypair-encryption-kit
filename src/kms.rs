use aws_config::meta::region::RegionProviderChain;
use aws_sdk_config::{config::Region, meta::PKG_VERSION};
use aws_sdk_kms::{types::KeySpec, Client as KmsClient};
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    /// The AWS Region.
    #[structopt(short, long)]
    region: Option<String>,

    /// The resource id.
    #[structopt(long)]
    resource_id: String,

    /// The resource type, eg. "AWS::EC2::SecurityGroup"
    #[structopt(long)]
    resource_type: String,

    /// Whether to display additional information.
    #[structopt(short, long)]
    verbose: bool,
}
use base64::{engine::general_purpose::STANDARD, Engine};

pub async fn encrypt_and_store_in_kms(
    base64_key: &str,
    key_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load AWS configuration from environment variables
    tracing_subscriber::fmt::init();

    let region_provider = RegionProviderChain::default_provider().or_else(Region::new("us-west-2"));

    println!();

    println!("Config client version: {}", PKG_VERSION);
    println!(
        "Region:                {}",
        region_provider.region().await.unwrap().as_ref()
    );
    println!();

    let shared_config = aws_config::from_env().region(region_provider).load().await;
    // let client = Client::new(&shared_config);

    let kms_client = KmsClient::new(&shared_config);

    let key_id = match key_id {
        Some(id) => id.to_string(),
        None => {
            let create_key_response = kms_client
                .create_key()
                .key_spec(KeySpec::SymmetricDefault)
                .description("Solana keypair encryption key")
                .send()
                .await?;

            create_key_response
                .key_metadata()
                .ok_or("No key metadata")?
                .key_id()
                .to_string()
        }
    };

    // Encrypt the base64 key
    let encrypt_response = kms_client
        .encrypt()
        .key_id(&key_id)
        .plaintext(base64_key.as_bytes().into())
        .send()
        .await?;

    println!("Encryped keypair to KMS key: {}", key_id);

    // Get the encrypted blob
    let ciphertext = encrypt_response.ciphertext_blob().unwrap();
    let ciphertext_bytes = ciphertext.as_ref();
    let encrypted_key = STANDARD.encode(ciphertext_bytes);

    Ok(encrypted_key)
}

pub async fn decrypt_with_kms(
    encrypted_key: &str,
    key_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Load AWS configuration from environment variables
    tracing_subscriber::fmt::init();

    let region_provider = RegionProviderChain::default_provider().or_else(Region::new("us-west-2"));

    println!();

    println!("Config client version: {}", PKG_VERSION);
    println!(
        "Region:                {}",
        region_provider.region().await.unwrap().as_ref()
    );
    println!();

    let shared_config = aws_config::from_env().region(region_provider).load().await;
    // let client = Client::new(&shared_config);

    let kms_client = KmsClient::new(&shared_config);

    let ciphertext = STANDARD.decode(encrypted_key)?;

    let decrypt_response = kms_client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(ciphertext.into())
        .send()
        .await?;

    let bytes = decrypt_response.plaintext().unwrap().as_ref();
    let s = String::from_utf8(bytes.to_vec()).expect("Could not convert to UTF-8");

    Ok(bytes.to_vec())
}
