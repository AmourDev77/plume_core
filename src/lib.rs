use std::{env, fmt::format, fs, io::BufRead};

use base64::{engine::general_purpose::URL_SAFE, Engine};
use ed25519_dalek::SecretKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod encryption;

/// Generate the basics configuration files along with default values
/// Path of the file is taken from the PLUME_CONFIG environment variable
pub fn init() {
    let config_path = env::var("PLUME_CONFIG").expect("PLUME_CONFIG environment variable not set");
    
    let exist = fs::exists(&config_path).expect("Unable to access config file : Permission denied");
    if exist {return};

    let json = serde_json::json!({
        "@me": {
            "username": "defaultUserName",
            "profilePicture": "None"
        },
        "friends": []
    });

    fs::create_dir_all(&config_path).expect("Unable to create config directory");
    fs::create_dir(format!("{}/transactions", &config_path)).expect("Unable to create transactions directory");

    fs::write(format!("{}/config.json", config_path), serde_json::to_vec(&json).expect("Unable to transform default json value")).expect("Unable to write file");
    println!("Wrote file")
}

pub fn request_friend() -> String {
    let config_path = env::var("PLUME_CONFIG").expect("Unable to access PLUME_CONFGI environment variable");
    let (secret, public_key) = encryption::generate_keys();


    // then store transaction
    let file_name = format!("friend-{}", public_key);
    let transaction = serde_json::json!({
        "public": public_key,
        "secret":  secret
    });

    fs::write(format!("{}/transactions/{}", config_path, file_name), serde_json::to_vec(&transaction).expect("Unable to create json data")).expect("Unable to create transaction file");

    public_key
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Transaction {
    public: String,
    secret: String
}

/// Generate the shared key used to encrypt messages and store it in the config file
pub fn add_friend(own_public_x: String, friend_public_x_base64: String, friend_public_ed: String, friend_username: String) -> bool {
    let config_path = env::var("PLUME_CONFIG").expect("Unable to access PLUME_CONFIG environment variable");
    let config_file = format!("{}/config.json", config_path);

    let decoded_friend_key: [u8; 32] = URL_SAFE.decode(friend_public_x_base64).expect("Error decrypting base64 key").try_into().expect("Invalid key provided");
    let friend_public_x = PublicKey::from(decoded_friend_key);
    
    let transaction_name = format!("friend-{}", own_public_x);
    let transaction_file = fs::File::open(format!("{}/{}", config_path, transaction_name)).expect("Unable to open transaction file");
    let transaction_data: Transaction = serde_json::from_reader(transaction_file).expect("Unable to read transaction file");

    let decoded_secret: [u8; 32] = URL_SAFE.decode(transaction_data.secret).expect("Invalid key, decryption failed").try_into().expect("Invalid key");
    let own_secret: StaticSecret = StaticSecret::from(decoded_secret);

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
