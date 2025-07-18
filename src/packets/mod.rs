pub mod friend_request;
pub mod relay_interactions;

pub enum PacketGenerationError {
    InvalidSingingKey,
    InvalidTargetEd,
    InvalidSharedKey,
}

impl ToString for PacketGenerationError {
    fn to_string(&self) -> String {
        match self {
            PacketGenerationError::InvalidTargetEd => {
                return String::from("Invalid target ED_25519 key provided")
            }
            PacketGenerationError::InvalidSharedKey => {
                return String::from("Invalid shared key provided")
            }
            PacketGenerationError::InvalidSingingKey => {
                return String::from("Invalid signing (private ED_25519) key provided")
            }
        }
    }
}


pub enum PacketReadingError {
    InvalidSignature,
    InvalidSharedKey,
    InvalidFormat
}

impl ToString for PacketReadingError {
    fn to_string(&self) -> String {
        match self {
            PacketReadingError::InvalidSignature => {
                return String::from("Packet has an invalid signature");
            }
            PacketReadingError::InvalidSharedKey => {
                return String::from("Unable to read payload, invalid shared key provided")
            }
            PacketReadingError::InvalidFormat => {
                return String::from("Invalid format")
            }
        }
    }
}
