use std::{env, fmt, str::FromStr};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature as EdSignature, VerifyingKey};

use crate::{encryption::signature::Signature, packets::{Packet, PacketReadingError}};


pub mod keys;
pub mod signature;

/// This function is used to encrypt the content of a message using the x25519 shared key
pub fn encrypt_payload(_message: &str, _shared_key: &str) -> String {
    todo!()
}


#[derive(Debug)]
pub struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid format")
    }
}

impl std::error::Error for FormatError {}

/// Verify the signature of a given packet.
/// Packet are sent in json format, each packet will have it's own way to make the signature
/// payload
///
/// # Formats
/// ## Login
/// Signed payload is simply composed of the author key
/// ## Messages
/// Signed payload is author_key + recipent_key + content + sent_at
/// ## Friend Request
/// ## Retrieve Published
pub fn verify_packet_signature(packet: &Packet) -> Result<(), PacketReadingError> {
    let environment = env::var("ENV").unwrap_or_default();

    // disable verify_packet_signature in dev env
    if environment == "DEV" {
        return Ok(())
    }

    let key = VerifyingKey::from_public_key_pem(packet.get_author_key())?;
    let signature = EdSignature::from_str(packet.get_signature())?;
    key.verify_strict(packet.get_signature_payload().as_bytes(), &signature)?;
    Ok(())
}
