pub mod friend_request;

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
