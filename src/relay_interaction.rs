use std::{env, fs};

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use base64::{engine::general_purpose::URL_SAFE, Engine};

/// Send a message to a relay with the following structure : message--author-<ed25519_pub>--target-<ed25519_pub>--<encryptedMessage_>--<signature>
/// This function will handle the message encryption and signature then it will send it to the relay
///
/// Signature will be made using author ed25519 key and the whole rest of the data sent to relay
///
/// Takes the following arguments (all keys must be given encoded in base64) :
/// String author_key = author ed25519 public key, this will be used to indicate which user sends the message
/// String target_key = target ed25519 public key, used to determine to whom the message is sent
/// String shared_key = key used for encryption
/// String signing_key = author private ed25519 key, used for signature of the message
/// String message = raw message to send
/// String relay_address = address / ip of a relay
pub fn send_message_relay(auhtor_key: String, target_key: String, shared_key: String, signing_key: String, message: String, relay_address: String) {
    todo!()
}

/// Send a friend request to a user using his ed25519 public key. This generates a combinaison of
/// x25519 keys which are returned
/// The followings arguments are needed : 
/// String target_key = Target ed25519 public key, will be stored
/// String author_key = Author ed25519 key
pub fn request_friend(target_key: String, auhtor_key: String) -> (String, String) {
    let config_path = env::var("PLUME_CONFIG").expect("Unable to access PLUME_CONFGI environment variable");
    let (secret, public_key) = encryption::generate_keys();


    // then store transaction
    let file_name = format!("friend-{}", public_key);
    let transaction = serde_json::json!({
        "public": public_key,
        "secret":  secret
    });

    fs::write(format!("{}/transactions/{}", config_path, file_name), serde_json::to_vec(&transaction).expect("Unable to create json data")).expect("Unable to create transaction file");

    (secret, public_key)
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

/// Generate a new transaction to ask a friend, 
pub fn add_friend(own_public_x: String, friend_public_x_base64: String, friend_public_ed: String, friend_username: String) -> bool {
    let config_path = env::var("PLUME_CONFIG").expect("Unable to access PLUME_CONFIG environment variable");
    let config_file = format!("{}/config.json", config_path);

    let decoded_friend_key: [u8; 32] = URL_SAFE.decode(friend_public_x_base64).expect("Error decrypting base64 key").try_into().expect("Invalid key provided");
    let friend_public_x = PublicKey::from(decoded_friend_key);
    
    let transaction_file = fs::File::open(format!("{}/{}", config_path, format!("friend-{}", own_public_x))).expect("Unable to open transaction file");
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

/// Create a transaction given the name and a body
pub fn create_transaction() -> String{
    let transaction_fil = fs::write(path, contents)
}
