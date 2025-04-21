use std::{env, fs};

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub enum TransactionError {
    UnknownKeyError()
}

pub fn generate_keys() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret); 
    
    (secret, public)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Me {
    username: String,
    public_ed: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Friend {
    username: String,
    public_ed: String,
    shared_key: [u8; 32]
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    me: Me,
    friends: Vec<Friend>
}

/// Generate the shared key used to encrypt messages and store it in the config file
pub fn generate_friend(own_secret: EphemeralSecret, friend_public_x: PublicKey, friend_public_ed: String, friend_username: String) -> bool {
    let config_path = env::var("PLUME_CONFIG").expect("Unable to access PLUME_CONFIG environment variable");
    let config_file = format!("{}/config.json", config_path);

    let shared = own_secret.diffie_hellman(&friend_public_x);

    let json_file = fs::File::open(&config_file).unwrap_or_else(|_| panic!("Failed to open configuration file at {}", config_path));
    let mut json: Config = serde_json::from_reader(json_file).expect("Invalid configuration file");

    let friend = Friend {
        username: friend_username,
        public_ed: friend_public_ed,
        shared_key: shared.to_bytes()
    };

    json.friends.push(friend);

    fs::write(config_file, serde_json::to_string(&json).expect("Error adding friend")).expect("");

    true
}
