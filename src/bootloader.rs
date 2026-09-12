use std::sync::Arc;

#[cfg(feature = "nitro")]
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo};
#[cfg(feature = "nitro")]
use base64::Engine;
#[cfg(feature = "nitro")]
use rsa::pkcs8::EncodePublicKey;
#[cfg(feature = "nitro")]
use secrecy::SecretString;

pub async fn load_proxy_auth_token() -> Result<Arc<String>, String> {
    #[cfg(feature = "nitro")]
    {
        let ciphertext = std::env::var("PROXY_AUTH_TOKEN_CIPHERTEXT").map_err(|_| {
            "PROXY_AUTH_TOKEN_CIPHERTEXT must be configured in Nitro mode".to_string()
        })?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(ciphertext.trim())
            .map_err(|error| format!("PROXY_AUTH_TOKEN_CIPHERTEXT is not valid Base64: {error}"))?;
        let token = decrypt_with_nsm(ciphertext).await?;
        return Ok(Arc::new(token.expose_secret().to_owned()));
    }

    #[cfg(not(feature = "nitro"))]
    {
        let token = std::env::var("PROXY_AUTH_TOKEN")
            .map_err(|_| "PROXY_AUTH_TOKEN must be configured outside Nitro mode".to_string())?;
        Ok(Arc::new(token))
    }
}

#[cfg(feature = "nitro")]
async fn decrypt_with_nsm(ciphertext: Vec<u8>) -> Result<SecretString, String> {
    crate::vsock_bridge::spawn_enclave_tunnels().await;
    std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:8000");
    std::env::set_var("https_proxy", "http://127.0.0.1:8000");
    std::env::set_var("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:8001");

    let private_key = tokio::task::spawn_blocking(|| {
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 3072)
            .map_err(|error| format!("failed to generate RSA recipient key: {error}"))
    })
    .await
    .map_err(|error| format!("RSA key generation task failed: {error}"))??;
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|error| format!("failed to encode RSA recipient key: {error}"))?;

    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        return Err("NSM initialization failed".to_string());
    }
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let response = tokio::task::spawn_blocking(move || {
        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(
            nsm_fd,
            aws_nitro_enclaves_nsm_api::api::Request::Attestation {
                nonce: Some(nonce.to_vec().into()),
                public_key: Some(public_key_der.as_bytes().to_vec().into()),
                user_data: None,
            },
        );
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
        response
    })
    .await
    .map_err(|error| format!("NSM request task failed: {error}"))?;
    let attestation_document = match response {
        aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
        other => return Err(format!("NSM attestation request failed: {other:?}")),
    };

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_kms::Client::new(&config);
    let recipient = RecipientInfo::builder()
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .attestation_document(aws_smithy_types::Blob::new(attestation_document))
        .build();
    let response = client
        .decrypt()
        .ciphertext_blob(aws_smithy_types::Blob::new(ciphertext))
        .recipient(recipient)
        .send()
        .await
        .map_err(|error| format!("AWS KMS attested decrypt failed: {error}"))?;
    let wrapped_plaintext = response
        .ciphertext_for_recipient()
        .ok_or_else(|| "AWS KMS response omitted CiphertextForRecipient".to_string())?
        .clone()
        .into_inner();
    let plaintext = tokio::task::spawn_blocking(move || {
        use rsa::Oaep;
        use sha2::Sha256;
        private_key
            .decrypt(Oaep::new::<Sha256>(), &wrapped_plaintext)
            .map_err(|error| format!("RSA recipient decryption failed: {error}"))
    })
    .await
    .map_err(|error| format!("RSA decryption task failed: {error}"))??;
    let token = String::from_utf8(plaintext)
        .map_err(|_| "AWS KMS plaintext token was not valid UTF-8".to_string())?;
    Ok(SecretString::new(token.into_boxed_str()))
}
