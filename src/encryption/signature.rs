use std::env;

use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};

use crate::packets::{Packet, PacketGenerationError};
pub trait Signature {
    fn get_signature_payload(&self) -> String;
    fn get_author_key(&self) -> &str;
    fn get_signature(&self) -> &str;
    fn update_signature(&mut self, signature: String);
}

impl Signature for Packet {
    fn get_signature_payload(&self) -> String {
        match self {
            Packet::Login(request_data) => {
                format!("{}{}", request_data.headers.action, request_data.headers.author_key)
            }
            Packet::Message(request_data) => {
                format!("{}{}{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.recipient, request_data.sent_at, request_data.content)
            }
            Packet::FriendRequest(request_data) => {
                format!("{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.recipient)
            }
            Packet::RetrievePublished(request_data) => {
                format!("{}{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.recipient, request_data.key)
            }
            Packet::Register(request_data) => {
                format!("{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.author_published)
            }
            Packet::Announcement(request_data) => {
                format!("{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.message)
            }
            Packet::Error(request_data) => {
                format!("{}{}{}", request_data.headers.action, request_data.headers.author_key, request_data.message)
            }
        }
    }

    fn get_author_key(&self) -> &str {
        match self {
            Packet::Login(request_data) => &request_data.headers.author_key,
            Packet::Message(request_data) => &request_data.headers.author_key,
            Packet::FriendRequest(request_data) => &request_data.headers.author_key,
            Packet::RetrievePublished(request_data) => &request_data.headers.author_key,
            Packet::Register(request_data) => &request_data.headers.author_key,
            Packet::Announcement(request_data) => &request_data.headers.author_key,
            Packet::Error(request_data) => &request_data.headers.author_key
        }
    }

    fn get_signature(&self) -> &str {
        match self {
            Packet::Login(request_data) => &request_data.headers.signature,
            Packet::Message(request_data) => &request_data.headers.signature,
            Packet::FriendRequest(request_data) => &request_data.headers.signature,
            Packet::RetrievePublished(request_data) => &request_data.headers.signature,
            Packet::Register(request_data) => &request_data.headers.signature,
            Packet::Announcement(request_data) => &request_data.headers.signature,
            Packet::Error(request_data) => &request_data.headers.signature
        }
    }

    fn update_signature(&mut self, signature: String) {
        match self {
            Packet::Login(request_data) => request_data.headers.signature = signature,
            Packet::Message(request_data) => request_data.headers.signature = signature,
            Packet::FriendRequest(request_data) => request_data.headers.signature = signature,
            Packet::RetrievePublished(request_data) => request_data.headers.signature = signature,
            Packet::Register(request_data) => request_data.headers.signature = signature,
            Packet::Announcement(request_data) => request_data.headers.signature = signature,
            Packet::Error(request_data) => request_data.headers.signature = signature
        }
    }
}

pub fn sign_packet(packet: &mut Packet, private_key: &str) -> Result<(), PacketGenerationError> {
    let env = env::var("ENV").unwrap_or_default();

    if env == "DEV" {
        packet.update_signature("<PacketSignature>".to_string());
        return Ok(());
    }

    let payload = packet.get_signature_payload();
    let key: SigningKey = SigningKey::from_pkcs8_pem(private_key)?;

    let signature = key.sign(payload.as_bytes());
    packet.update_signature(signature.to_string());
    Ok(())
}
