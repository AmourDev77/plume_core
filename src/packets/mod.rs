use std::{fmt::Display, fs};

use ed25519_dalek::{ed25519::signature, pkcs8::{self, spki}};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encryption::verify_packet_signature;

/// Differents types of packets, all new packets will be added here
pub enum Packet {
    Login(LoginData),
    Message(MessageData),
    FriendRequest(FriendRequestData),
    RetrievePublished(RetrievePublishedData),
    Register(RegisterData),
    Announcement(AnnouncementData),
    Error(ErrorData),
}

#[derive(Debug)]
pub enum PacketGenerationError {
    SingingKey,
    EDKey,
    SharedKey,
    PayloadSerialisation(serde_json::Error)
}

impl Display for PacketGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketGenerationError::EDKey => {
                write!(f, "Invalid ED_25519 key provided")?;
                Ok(())
            }
            PacketGenerationError::SharedKey => {
                write!(f, "Invalid shared key provided")?;
                Ok(())
            }
            PacketGenerationError::SingingKey => {
                write!(f, "Invalid signing (private ED_25519) key provided")?;
                Ok(())
            }
            PacketGenerationError::PayloadSerialisation(e) => {
                write!(f, "{e}")?;
                Ok(())
            }
        }
    }
}

impl From<serde_json::Error> for PacketGenerationError {
    fn from(value: serde_json::Error) -> Self {
        PacketGenerationError::PayloadSerialisation(value)
    }
}

impl From<pkcs8::Error> for PacketGenerationError {
    fn from(_: pkcs8::Error) -> Self {
        PacketGenerationError::SingingKey
    }
}

pub enum PacketReadingError {
    Signature,
    Key,
    Type,
    Data
}

impl Display for PacketReadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketReadingError::Signature => {
                write!(f, "Packet has an invalid signature")?;
                Ok(())
            }
            PacketReadingError::Key => {
                write!(f, "Unable to read payload, invalid shared key provided")?;
                Ok(())
            }
            PacketReadingError::Type => {
                write!(f, "Invalid format")?;
                Ok(())
            }
            PacketReadingError::Data => {
                write!(f, "Missing data in the packet")?;
                Ok(())
            }
        }
    }
}


impl From<serde_json::Error> for PacketReadingError {
    fn from(_: serde_json::Error) -> Self {
        PacketReadingError::Data
    }
}

impl From<spki::Error> for PacketReadingError {
    fn from(_: spki::Error) -> Self {
        PacketReadingError::Key
    }
}


impl From<signature::Error> for PacketReadingError {
    fn from(_: signature::Error) -> Self {
        PacketReadingError::Signature
    }
}


#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PacketHeader {
    pub action: String,
    pub author_key: String,
    pub signature: String
}


/// Data provided for the message packet
/// Date is in ISO 8601 format
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MessageData {
    pub headers: PacketHeader,
    pub recipient: String,
    pub sent_at: String, 
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LoginData {
    pub headers: PacketHeader
}

/// Registeration phase is for the first time you log in into a relay ever. 
/// This phase is needed for the friend request process as the users will need to retrieve keys
/// sent to the relay during the registeration phase
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RegisterData {
    pub headers: PacketHeader,
    pub author_published: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FriendRequestData {
    pub headers: PacketHeader,
    pub recipient: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RetrievePublishedData {
    pub headers: PacketHeader,
    pub recipient: String,
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ErrorData {
    pub headers: PacketHeader,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AnnouncementData {
    pub headers: PacketHeader,
    pub message: String,
}


pub trait RelayPacketGeneration {
    fn new(content: &str) -> Self;
}

/// Signature payload of the RelayMessage is action + relay_key + content
impl RelayPacketGeneration for ErrorData {
    fn new(message: &str) -> Self {
        let relay_config = crate::config::get_config();
        let relay_key = fs::read_to_string(relay_config.me.public_ed_path).expect("Couldn't read relay public key");

        Self {
            headers: PacketHeader {
                action: String::from("error"),
                author_key: relay_key,
                signature: String::default()
            },
            message: message.to_string(),
        }
    }
}


impl RelayPacketGeneration for AnnouncementData {
    fn new(message: &str) -> Self {
        let relay_config = crate::config::get_config();
        let relay_key = fs::read_to_string(relay_config.me.public_ed_path).expect("Couldn't read relay public key");

        Self {
            headers: PacketHeader {
                action: String::from("announcement"),
                author_key: relay_key,
                signature: String::default()
            },
            message: message.to_string(),
        }
    }
}

/// Transform a json string into a packet with all the necessary data and verify it's signature
///
/// packet_data is a collections or all the data required for this packet in order and split by "__".  
/// **Example**:
/// ```rust
/// use plume::packet;
///
/// let login_packet = r#"
///     {
///         "type": "login",
///         "author_key": "<MyKey>"
///     }"#;
/// let received = String::from(login_packet);
/// let packet: Packet = extract_packet(received);
/// ```
///
pub fn extract_and_verify (data: &str) -> Result<Packet, PacketReadingError> {
    let packet = extract(data)?;

    verify_packet_signature(&packet)?;

    Ok(packet)
}

pub fn extract(data: &str) -> Result<Packet, PacketReadingError> {
    let packet: Value = serde_json::from_str(data)?;
    let packet_type = packet["headers"]["action"].as_str().unwrap_or_default();
    println!("Packet Type is : {}", packet_type);

    match packet_type {
        "login" => {
            Ok(Packet::Login(serde_json::from_str(data)?))
        }
        "message" => {
            Ok(Packet::Message(serde_json::from_str(data)?))
        }
        "friend_request" => {
            Ok(Packet::FriendRequest(serde_json::from_str(data)?))
        }
        "retrieve_published" => {
            todo!("Generate the handle of this action")
        }
        "register" => {
            Ok(Packet::Register(serde_json::from_str(data)?))
        }
        _ => {
            Err(PacketReadingError::Type)
        }
    }
}
