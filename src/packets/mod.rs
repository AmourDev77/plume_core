use std::fmt::Display;
pub mod relay;

#[derive(Debug)]
pub enum PacketGenerationError {
    InvalidSingingKey,
    InvalidTargetEd,
    InvalidSharedKey,
    InvalidPayloadSerialisation(serde_json::Error)
}

impl Display for PacketGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketGenerationError::InvalidTargetEd => {
                write!(f, "Invalid target ED_25519 key provided")?;
                Ok(())
            }
            PacketGenerationError::InvalidSharedKey => {
                write!(f, "Invalid shared key provided")?;
                Ok(())
            }
            PacketGenerationError::InvalidSingingKey => {
                write!(f, "Invalid signing (private ED_25519) key provided")?;
                Ok(())
            }
            PacketGenerationError::InvalidPayloadSerialisation(e) => {
                write!(f, "{e}")?;
                Ok(())
            }
        }
    }
}

impl From<serde_json::Error> for PacketGenerationError {
    fn from(value: serde_json::Error) -> Self {
        PacketGenerationError::InvalidPayloadSerialisation(value)
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
