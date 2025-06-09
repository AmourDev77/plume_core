use std::{env, fs};

pub mod encryption;
pub mod relay_interaction;
pub mod config;

/// Generate the basics configuration files along with default values
/// Path of the file is taken from the PLUME_CONFIG environment variable
pub fn init() {
    println!("Writing file");
    let config_path = env::var("PLUME_CONFIG").expect("PLUME_CONFIG environment variable not set");
    
    let exist = std::fs::exists(&config_path).expect("Unable to access config folder");
    if exist {return};

    let json = serde_json::json!({
        "@me": {
            "public_ed_path": "",
            "private_ed_path": "",
            "username": "defaultUserName",
            "profile_picture": "None"
        },
        "friends": {},
        "friend_requests": {}
    });

    println!("Creating folders");
    fs::create_dir_all(&config_path).expect("Unable to create config directory");
    fs::create_dir(format!("{}/transactions", &config_path)).expect("Unable to create transactions directory");
    fs::create_dir(format!("{}/keys", &config_path)).expect("Unable to create keys directory"); // This directory will store users keys, friends keys will be stored directly in the json

    fs::write(format!("{}/configs.json", config_path), serde_json::to_vec(&json).expect("Unable to transform default json value")).expect("Unable to write file");

    println!("Wrote file");
}
