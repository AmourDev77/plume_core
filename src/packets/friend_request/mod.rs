use std::fs;

use crate::{config::{self, Friend, Me}, encryption::{self, sign_packet}};

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
pub fn retrieve_published_x(target_public_ed: &str) -> Result<String, std::io::Error> {
    // Result would be retrieve_shared_x__<author_public_ed>__<target_public_ed>__<signature>

    let author_public_ed = fs::read_to_string(config::get_config().me.public_ed_path)?;
    let author_private_ed = fs::read_to_string(config::get_config().me.private_ed_path)?;

    let packet = format!("retrieve_shared_x__{}__{}", author_public_ed, target_public_ed);

    return Ok(sign_packet(packet, &author_private_ed))
}

/// Generates the friend request packet with the provided details.
/// 
/// # Arguments
/// 
/// * `target_public_ed` - A string slice that holds the target's public key in ED25519 format.
/// * `author_signing_key` - A string slice that holds the author's signing key.
/// * `shared_key` - A string slice representing the shared encryption key.
/// * `author_data` - The author's data structure containing relevant information.
/// * `author_x_public_key` - A string slice holding the author's x25519 public key.
/// 
/// # Description
/// This function generates a friend request packet that contains all the necessary details
/// to initiate communication with a friend.
pub fn generate_friend_request_packet(target_public_ed: &str, author_signing_key: &str, shared_key: &str, author_data: Me, author_x_public_key: &str) -> Result<String, super::PacketGenerationError> {
    todo!("Generate the friend request packet")
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
pub fn retrieve_friend_data(packet: &str, shared_key: &str) -> Result<Friend,super::PacketReadingError> {
    // Structure of friend request : 
    // friend_request__author_public_ed__target_public_ed__data(json encrypted)__signature

    // First verify it is a friend request + verify the signature
    
    todo!()

}

#[cfg(test)]
mod tests {
    mod retrieve_published_x {
        #[test]
        #[ignore = "not implemented yet"]
        fn correct_call() {
            todo!("Generate the test for a correct call to the function")
        }

        #[test]
        #[ignore = "not implemented yet"]
        fn invalid_signing_key() {
            todo!("Generate test using an invalid signing key");
        }

        #[test]
        #[ignore = "Not implented yet"]
        fn invalid_target_ed() {
            todo!("Call function by providing a wrong ED structure, should return an error")
        }
    }

    mod generate_friend_request_packet {

    }
}
