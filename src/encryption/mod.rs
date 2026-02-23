use std::{fmt};

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

