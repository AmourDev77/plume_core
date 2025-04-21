use std::{env, fs};

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
