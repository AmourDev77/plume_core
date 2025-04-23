use base64::{engine::general_purpose::URL_SAFE, Engine};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

pub enum TransactionError {
    UnknownKeyError()
}

pub fn generate_keys() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret); 

    let base64_public =URL_SAFE.encode(public);
    let base64_private = URL_SAFE.encode(secret);
    
    (base64_private, base64_public)
}

