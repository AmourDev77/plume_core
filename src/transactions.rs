use std::{env, fmt::Display, fs};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub enum TransactionType {
    FriendRequest
}

impl Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionType::FriendRequest => {
                write!(f, "friend_request")
            }
        }
    }
}

#[derive(Serialize)]
pub struct Transaction {
    transaction_type: TransactionType,
    target_ed: String,
    status: bool
}

#[derive(Debug)]
pub enum StorageError {
    EnvVarNotSet(String),
    Serialization(serde_json::Error),
    Io(std::io::Error),
} 

impl Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::EnvVarNotSet(env) => {
                write!(f, "{}: environment variable not set or inaccessible", env)
                // Note: removed the semicolon - write! returns Result already
            }
            StorageError::Serialization(e) => {
                write!(f, "Serialization error: {}", e)
            }
            StorageError::Io(e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}
impl std::error::Error for StorageError {}


pub fn store(transaction: Transaction) -> Result<String, StorageError> {
    let config_path = env::var("PLUME_CONFIG")?;
    let transaction_id = Uuid::new_v4();

    let json_value = serde_json::to_vec(&serde_json::to_value(transaction)?)?;
    fs::write(format!("{config_path}/transactions/{transaction_id}"), json_value)?;

    Ok(transaction_id.to_string())
}

// Storage eror handling, putting boilerplate code after useful onnes

impl From<std::env::VarError> for StorageError {
    fn from(_: std::env::VarError) -> Self {
        StorageError::EnvVarNotSet("PLUME_CONFIG".to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}
