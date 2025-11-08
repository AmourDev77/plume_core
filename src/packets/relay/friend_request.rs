use serde::Serialize;
use crate::packets::{PacketReadingError, PacketGenerationError};

use crate::{config::Friend, encryption::{self, sign_packet}};

/// Generates a packet requesting a relay to provide the target's public x25519 key.
/// 
/// # Arguments
/// 
/// * `target_public_ed` - A string slice that holds the target's public key in ED25519 format.
/// * `author_signing_key` - A string slice that holds the author's signing key.
/// 
/// # Returns
/// 
/// A `Result` containing:
/// - `Ok(String)` with the target public x25519 key.
/// - `Err(PacketGenerationError)` if an error occurs during packet generation.
pub fn retrieve_published_x(target_public_ed: &str, author_public_ed: &str, author_private_ed: &str) -> Result<String, std::io::Error> {
    // Result would be retrieve_shared_x__<author_public_ed>__<target_public_ed>__<signature>
    let packet = format!("retrieve_published__{author_public_ed}__{target_public_ed}");
    Ok(sign_packet(packet, author_private_ed))
}



pub struct AuthorInfo<'a> {
    pub author_name: &'a str,
    pub author_private_ed: &'a str,
    pub author_public_ed: &'a str,
    pub author_picture: &'a str
}


/// Generates the friend request packet with the provided details.
/// 
/// # Arguments
/// 
/// * `target_public_ed` - A string slice that holds the target's public key in ED25519 format.
/// * `author_data` - The author's data structure containing relevant information.
/// * `shared_key` - A string slice representing the shared encryption key.
/// 
/// # Description
/// This function generates a friend request packet that contains all the necessary details
/// to initiate communication with a friend.
/// Payload is an encrypted striglified json of the user data
pub fn generate_friend_request_packet(target_public_ed: &str, author_data: AuthorInfo, shared_key: &str) -> Result<String, PacketGenerationError> {
    #[derive(Serialize)]
    struct Payload<'a > {
        username: &'a str,
        profile_picture: &'a str,
    }

    let payload = Payload{
        username: author_data.author_name,
        profile_picture: author_data.author_picture
    };

    let message = serde_json::to_string(&payload)?;
    let encrypted_data = encryption::encrypt_payload(&message,shared_key);
    let packet = format!("friend_request__{}__{}__{}", author_data.author_public_ed, target_public_ed, encrypted_data);


    Ok(sign_packet(packet, author_data.author_private_ed))
}

/// Processes the received friend request packet to retrieve the friend's data.
/// 
/// # Arguments
/// 
/// * `packet` - A string representing the packet containing friend's information.
/// * `shared_key` - A shared key used to decrypt the payload data
/// 
/// # Description
/// Parses the provided packet and extracts friend's relevant data for further actions.
pub fn retrieve_friend_data(packet: &str, shared_key: &str) -> Result<Friend,PacketReadingError> {
    // Structure of friend request : 
    // friend_request__author_public_ed__target_public_ed__data(json encrypted)__signature

    // First verify it is a friend request + verify the signature
    todo!()
}
