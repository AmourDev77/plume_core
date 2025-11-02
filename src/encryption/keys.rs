use base64::{engine::general_purpose::URL_SAFE, DecodeError, Engine};
use ed25519_dalek::{pkcs8::{EncodePrivateKey, EncodePublicKey}, SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::PublicKey;

/// Generate a x25519 key combinaison
///
/// returns !
/// 
/// (base64_private: String, base64_public: String)
/// 
pub fn generate_x_keys() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret); 

    let base64_public =URL_SAFE.encode(public);
    let base64_private = URL_SAFE.encode(secret);
    
    (base64_private, base64_public)
}

/// This function generate an ed25519 signingkey and an associated public key and returns their
/// PKCS#8 PEM form following this order : (private: String, public: String)
pub fn generate_ed_keys() -> (String, String) {
    let mut csprng = OsRng;

    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let encoded_private = signing_key.to_pkcs8_pem(Default::default()).expect("Failed to encode private key to PKCS#8 PEM").to_string();
    let encoded_public = verifying_key.to_public_key_pem(Default::default()).expect("Failed to encode private key to PKCS#8 PEM");

    (encoded_private, encoded_public)
}



#[derive(Debug)]
pub enum SharedGenerationError {
    InvalidKeyError,
    DecodeError
}

// Important for the "?" to be usable when using URL_SAFE.decode
impl From<DecodeError> for SharedGenerationError {
    fn from(_: DecodeError) -> Self {
        SharedGenerationError::DecodeError
    }
}

impl From<Vec<u8>> for SharedGenerationError {
    fn from(_: Vec<u8>) -> Self {
        SharedGenerationError::InvalidKeyError
    }
}

/// Function Generate a shared key from two keys.
/// String user_private = user private x25519 key
/// Stirng target_public = user public w25519 key
pub fn generate_shared_key(user_private: &str, target_public: &str) -> Result<String, SharedGenerationError>  {
    // first unhash the two keys
    let decoded_private: [u8; 32] = URL_SAFE.decode(user_private)?.try_into()?;
    let decoded_public: [u8; 32] = URL_SAFE.decode(target_public)?.try_into()?;

    let private = x25519_dalek::StaticSecret::from(decoded_private);
    let public = x25519_dalek::PublicKey::from(decoded_public);

    let shared = private.diffie_hellman(&public);

    Ok(URL_SAFE.encode(shared))
}
