use async_trait::async_trait;
use secrecy::SecretString;
use std::sync::Arc;
use tracing::{debug, info};

#[cfg(feature = "nitro")]
use base64::Engine as _;

#[async_trait]
pub trait KmsProvider: Send + Sync {
    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<SecretString, String>;
}

#[cfg(all(debug_assertions, not(feature = "nitro")))]
pub struct LocalMockProvider {
    client: aws_sdk_kms::Client,
}

#[cfg(all(debug_assertions, not(feature = "nitro")))]
impl LocalMockProvider {
    pub async fn new() -> Result<Self, String> {
        let endpoint = std::env::var("LOCALSTACK_ENDPOINT")
            .map_err(|_| "LOCALSTACK_ENDPOINT is required for LocalMockProvider".to_string())?;
        let region = std::env::var("AWS_DEFAULT_REGION")
            .or_else(|_| std::env::var("AWS_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_string());
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .endpoint_url(endpoint)
            .load()
            .await;
        Ok(Self {
            client: aws_sdk_kms::Client::new(&config),
        })
    }
}

#[cfg(all(debug_assertions, not(feature = "nitro")))]
#[async_trait]
impl KmsProvider for LocalMockProvider {
    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<SecretString, String> {
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext))
            .send()
            .await
            .map_err(|error| format!("LocalStack KMS decrypt failed: {error}"))?;
        let plaintext = response
            .plaintext
            .ok_or_else(|| "LocalStack KMS response did not contain plaintext".to_string())?;
        let plaintext = String::from_utf8(plaintext.into_inner())
            .map_err(|_| "LocalStack KMS plaintext was not valid UTF-8".to_string())?;
        Ok(SecretString::new(plaintext.into_boxed_str()))
    }
}

#[cfg(feature = "nitro")]
pub struct NitroKmsProvider;

#[cfg(feature = "nitro")]
impl NitroKmsProvider {
    pub async fn new() -> Result<Self, String> {
        Ok(Self)
    }
}

#[cfg(feature = "nitro")]
#[async_trait]
impl KmsProvider for NitroKmsProvider {
    async fn decrypt(&self, ciphertext: Vec<u8>) -> Result<SecretString, String> {
        crate::vsock_bridge::spawn_enclave_tunnels().await;
        std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:8000");
        std::env::set_var("https_proxy", "http://127.0.0.1:8000");
        std::env::set_var(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
            "http://127.0.0.1:8001",
        );

        let config = aws_config::load_from_env().await;
        let client = aws_sdk_kms::Client::new(&config);
        let (private_key, public_key_der) = tokio::task::spawn_blocking(|| {
            let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 3072)
                .map_err(|error| format!("Failed to generate RSA keypair: {error}"))?;
            let public_key_der = rsa::spki::EncodePublicKey::to_public_key_der(
                &private_key.to_public_key(),
            )
            .map_err(|error| format!("Failed to encode SPKI public key: {error}"))?
            .as_bytes()
            .to_vec();
            Ok::<_, String>((private_key, public_key_der))
        })
        .await
        .map_err(|error| format!("RSA key generation task failed: {error}"))??;

        let nsm_fd = std::fs::File::open("/dev/nsm")
            .map_err(|error| format!("Failed to open /dev/nsm: {error}"))?;
        use std::os::fd::AsRawFd;
        let attestation_response = tokio::task::spawn_blocking(move || {
            aws_nitro_enclaves_nsm_api::driver::nsm_process_request(
                nsm_fd.as_raw_fd(),
                aws_nitro_enclaves_nsm_api::api::Request::Attestation {
                    nonce: None,
                    public_key: Some(public_key_der),
                    user_data: None,
                },
            )
        })
        .await
        .map_err(|error| format!("NSM request task failed: {error}"))?;
        let attestation_document = match attestation_response {
            aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
            other => return Err(format!("NSM attestation request failed: {other:?}")),
        };

        let recipient = aws_sdk_kms::types::RecipientInfo::builder()
            .key_encryption_algorithm(
                aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
            )
            .attestation_document(aws_smithy_types::Blob::new(attestation_document))
            .build();
        let response = client
            .decrypt()
            .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext))
            .recipient(recipient)
            .send()
            .await
            .map_err(|error| format!("AWS KMS decrypt failed: {error}"))?;
        let ciphertext_for_recipient = response
            .ciphertext_for_recipient()
            .ok_or_else(|| "AWS KMS response did not contain CiphertextForRecipient".to_string())?
            .clone()
            .into_inner();
        let plaintext = tokio::task::spawn_blocking(move || {
            use rsa::Oaep;
            use sha2::Sha256;
            private_key
                .decrypt(Oaep::new::<Sha256>(), &ciphertext_for_recipient)
                .map_err(|error| format!("RSA-OAEP decryption failed: {error}"))
        })
        .await
        .map_err(|error| format!("RSA decryption task failed: {error}"))??;
        let plaintext = String::from_utf8(plaintext)
            .map_err(|_| "AWS KMS plaintext was not valid UTF-8".to_string())?;
        Ok(SecretString::new(plaintext.into_boxed_str()))
    }
}

pub async fn decrypt_upstream_api_key(
    provider: Arc<dyn KmsProvider>,
    ciphertext: Vec<u8>,
) -> Result<SecretString, String> {
    info!("Starting KMS decrypt flow for upstream API key");
    let secret = provider.decrypt(ciphertext).await?;
    debug!("KMS returned the upstream API key in a protected container");
    Ok(secret)
}
