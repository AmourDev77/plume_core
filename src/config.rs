use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(rename = "@me")]
    pub me: Me,
    pub friends: Vec<Friend>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Friend {
    pub public_ed: String,
    pub shared_kiey: String,
    pub username: String,
    pub profile_picture: String,
    pub last_sync: String // May be modified to a date format
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Me {
    pub public_ed_path: String,
    pub private_ed_path: String,
    pub username: String,
    pub profile_picture: String
}
