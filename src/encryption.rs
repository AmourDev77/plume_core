use base64::{engine::general_purpose::URL_SAFE, Engine};
use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey}, SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::PublicKey;

pub enum TransactionError {
    UnknownKeyError()
}

/// Generate a x25519 key combinaison
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

    return (encoded_private, encoded_public)
}


/// Function Generate a shared key from two keys.
/// String user_private = user private x25519 key
/// Stirng target_public = user public w25519 key
pub fn generate_shared_key(user_private: String, target_public: String) -> String {
    todo!()
}


// ---------- Key usage ----------

/// This function will encrypt a message using the given key.
/// Key must be given in pkcs8 encoded format
pub fn sign_packet(packet: String, key: &str) -> String {
    let mut key: SigningKey = SigningKey::from_pkcs8_pem(&key).expect("Invalid Signing key provided, unable to send packet");


    let signature = key.try_sign(packet.as_bytes()).expect("Error signing packet");
    format!("{}__{}", packet, signature)
}
