use serde::Serialize;

use crate::{config::{Friend, UserInformation}, encryption::{self, sign_packet}};

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
/// Payload is a striglified json of the user data
pub fn generate_friend_request_packet(target_public_ed: &str, user_information: UserInformation<'_>, shared_key: &str) -> Result<String, super::PacketGenerationError> {
    #[derive(Serialize)]
    struct Payload<'a > {
        username: &'a str,
        profile_picture: &'a str,
    }

    let payload = Payload{
        username: user_information.username,
        profile_picture: user_information.profile_picture
    };

    let message = serde_json::to_string(&payload)?;
    let encrypted_data = encryption::encrypt_payload(&message,shared_key);
    let packet = format!("friend_request__{}__{}__{}", user_information.author_public_ed, target_public_ed, encrypted_data);


    Ok(sign_packet(packet, user_information.author_private_ed))
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
    const TARGET_PUBLIC_ED: &str = "<target_ed>";
    const AUTHOR_PUBLIC_ED: &str = "<author_ed>";
    const AUTHOR_PRIVATE_ED: &str = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIDYl6V3dZDi6Q/waB+XyLEv2bjdnNXoas2fpaSPFm+up
gSEAiCd7Td+qdVFItJIHnRfszO9cnl+fcL/W2AIzCBuYsBE=
-----END PRIVATE KEY-----";
    const AUTHOR_PUBLIC_PUBLISHED: &str = "Ee3MVPKBV7kbheEjlrdGUb7oucuHa8bt76OFUsCUCCo=";
    const AUTHOR_PRIVATE_PUBLISHED: &str = "ZeTbRwCQ7Q3rnItXOIOzkDSa7sqhZYFq-ieVxc5rrps=";
    const TARGET_PUBLIC_PUBLISHED: &str = "2qS-T-dzmbNr9z3Y1ynfuKBSjASLLVC1TbwgyINCEgc=";




    mod retrieve_published_x {
        use super::{AUTHOR_PUBLIC_ED, TARGET_PUBLIC_ED, AUTHOR_PRIVATE_ED};
        use crate::packets::friend_request::retrieve_published_x;

        #[test]
        fn correct_call() {

            let result = retrieve_published_x(TARGET_PUBLIC_ED, AUTHOR_PUBLIC_ED, AUTHOR_PRIVATE_ED);
            assert_eq!(result.unwrap(), "retrieve_published__<author_ed>__<target_ed>__C8E5645E3103C15BE6FDF9AFFCD5EB5B84B11F8F15A999D7349CCE074C7099BD62E3E7D93733B706E1326880021BDBC7AA66DDD1CE967EFB7533F05300C6610C");
        }

        #[test]
        fn invalid_signing_key() {
            let result = retrieve_published_x(TARGET_PUBLIC_ED, AUTHOR_PUBLIC_ED, AUTHOR_PRIVATE_ED);

            assert!(result.is_err())
        }

        #[test]
        #[ignore = "Not implented yet"]
        fn invalid_target_ed() {
            todo!("Call function by providing a wrong ED structure, should return an error")
        }
    }

    mod generate_friend_request_packet {
        use crate::{config::UserInformation, encryption::generate_shared_key, packets::{self, friend_request::generate_friend_request_packet}};
        use super::{AUTHOR_PRIVATE_ED, AUTHOR_PUBLIC_ED, TARGET_PUBLIC_ED, AUTHOR_PUBLIC_PUBLISHED, AUTHOR_PRIVATE_PUBLISHED, TARGET_PUBLIC_PUBLISHED};

        #[test]
        fn test_valid_data() {
            let user_information = UserInformation {
                author_public_ed: AUTHOR_PUBLIC_ED,
                author_private_ed: AUTHOR_PRIVATE_ED,
                author_public_published: AUTHOR_PUBLIC_PUBLISHED,
                author_private_published: AUTHOR_PRIVATE_PUBLISHED,
                username: "<username>",
                profile_picture: "<profile_picture>"
            };

            let shared_key = generate_shared_key(AUTHOR_PRIVATE_PUBLISHED, TARGET_PUBLIC_PUBLISHED).unwrap();

            let packet = generate_friend_request_packet(TARGET_PUBLIC_ED, user_information, &shared_key).unwrap();

            assert_eq!(packet, "");
        }

        #[test]
        fn test_invalid_shared_key() {
            let user_information = UserInformation {
                author_public_ed: AUTHOR_PUBLIC_ED,
                author_private_ed: AUTHOR_PRIVATE_ED,
                author_public_published: AUTHOR_PUBLIC_PUBLISHED,
                author_private_published: AUTHOR_PRIVATE_PUBLISHED,
                username: "<username>",
                profile_picture: "<profile_picture>"
            };

            let shared_key = "Invalid".to_string();

            let packet = generate_friend_request_packet(TARGET_PUBLIC_ED, user_information, &shared_key);
        }
    }
}
