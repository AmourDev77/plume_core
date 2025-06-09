use std::{collections::HashMap, env, fs::{self, File}, io::BufReader};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(rename = "@me")]
    pub me: Me,
    pub friends: HashMap<String, Friend>,
    pub friend_requests: HashMap<String, FriendRequest>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Friend {
    pub private_x: String,
    pub public_ed: String,
    pub shared_key: String,
    pub username: String,
    pub profile_picture: String,
    pub last_sync: String // May be modified to a date format
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Me {
    pub public_ed_path: String,
    pub private_ed_path: String,
    pub username: String,
    pub profile_picture: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FriendRequest {
    pub friend_public_ed: String,
    pub friend_public_x: String,
    pub username: String,
    pub profile_picture: String,
}

/// This function update the config file of the user. 
/// Arguments : 
/// Config config = the new config to be written.
pub fn update_config(config: &Config) {
    let config_path = env::var("PLUME_CONFIG").expect("Config env var not set");
    fs::write(format!("{}/configs.json", config_path),  serde_json::to_vec(&config).expect("Unable to transform string to json")).expect("Unable to write config file");
}

pub fn get_config() -> Config {
    let config_path = env::var("PLUME_CONFIG").expect("Config env var not set");
    let config_file = File::open(format!("{}/configs.json", config_path)).expect("Eror opening config file");
    let reader = BufReader::new(config_file);

    serde_json::from_reader(reader).expect("Unable to convert this file to json")
}
