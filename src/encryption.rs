use base64::{engine::general_purpose::URL_SAFE, Engine};
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

/// This function generates ed25519 keys
pub fn generate_ed_keys() -> (String, String) {
    todo!()
}


/// Function Generate a shared key from two keys.
/// String user_private = user private x25519 key
/// Stirng target_public = user public w25519 key
pub fn generate_shared_key(user_private: String, target_public: String) -> String {
    todo!()
}
