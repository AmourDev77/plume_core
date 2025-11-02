use std::fmt::Display;
pub mod relay;

#[derive(Debug)]
pub enum PacketGenerationError {
    InvalidSingingKey,
    InvalidED,
    InvalidSharedKey,
    InvalidPayloadSerialisation(serde_json::Error)
}

impl Display for PacketGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketGenerationError::InvalidED => {
                write!(f, "Invalid ED_25519 key provided")?;
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

impl Display for PacketReadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketReadingError::InvalidSignature => {
                write!(f, "Packet has an invalid signature")?;
                Ok(())
            }
            PacketReadingError::InvalidSharedKey => {
                write!(f, "Unable to read payload, invalid shared key provided")?;
                Ok(())
            }
            PacketReadingError::InvalidFormat => {
                write!(f, "Invalid format")?;
                Ok(())
            }
        }
    }
}
