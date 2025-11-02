use std::{env, fs};

use crate::encryption::keys::{generate_ed_keys, generate_x_keys};

pub mod packets;
pub mod encryption;
pub mod config;

/// Generate the basics configuration files along with default values
/// Path of the file is taken from the PLUME_CONFIG environment variable
pub fn init() {
    println!("Writing file");
    let config_path = env::var("PLUME_CONFIG").expect("PLUME_CONFIG environment variable not set");
    
    let exist = std::fs::exists(&config_path).expect("Unable to access config folder");
    if exist {return};


    // creating all the necessary folders
    println!("Creating folders");
    fs::create_dir_all(&config_path).expect("Unable to create config directory");
    fs::create_dir(format!("{}/transactions", &config_path)).expect("Unable to create transactions directory");
    fs::create_dir(format!("{}/keys", &config_path)).expect("Unable to create keys directory"); // This directory will store users keys, friends keys will be stored directly in the json
    println!("Creating keys");


    // for each needed key, create one
    let (private_ed, public_ed) = generate_ed_keys();
    let (private_published, public_published) = generate_x_keys();
    fs::write(format!("{config_path}/keys/private_ed.pem"), private_ed).expect("Unable to write pivate ed key to disk");
    fs::write(format!("{config_path}/keys/public_ed.pem"), public_ed).expect("Unable to write pivate ed key to disk");
    fs::write(format!("{config_path}/keys/public_published.pem"), public_published).expect("Unable to write pivate ed key to disk");
    fs::write(format!("{config_path}/keys/private_published.pem"), private_published).expect("Unable to write pivate ed key to disk");

    println!("Keys saved");

    // generate the configurat_ion
    let json = serde_json::json!({
        "@me": {
            "public_ed_path": format!("{config_path}/keys/public_ed.pem"),
            "private_ed_path": format!("{config_path}/keys/private_ed.pem"),
            "username": "defaultUserName",
            "profile_picture": "None",
            "public_published_path": format!("{config_path}/keys/public_published.pem"),
            "private_published_path": format!("{config_path}/keys/private_published.pem")
        },
        "friends": {},
        "friend_requests": {}
    });

    fs::write(format!("{}/configs.json", config_path), serde_json::to_vec(&json).expect("Unable to transform default json value")).expect("Unable to write file");

    println!("Wrote file");
}

#[cfg(test)]
mod test {
    use std::{env, fs};

    use dotenv::dotenv;
    use crate::{config::get_config, init};

    #[test]
    fn test_initialisation() {
        dotenv().ok();
        let config_path = env::var("PLUME_CONFIG").expect("Unableto access env var");
        // first, delete config folder if it already exist
        if fs::exists(&config_path).expect("Unable to access config folder location") {
            fs::remove_dir_all(config_path).expect("Unable to delete config folder");
        }
        init();
        // then read the file and try to convert it again to json
        let config = get_config();
        assert_eq!(config.me.username, "defaultUserName");
    }
}
