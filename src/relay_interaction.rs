use crate::encryption;

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

/// Generates the packet which is needed to send a friend request, also generates the requred x25519 keys which are returned in base64.
///
/// Final return is an array of length 3 which contains : [packet, author_x_public, author_x_private]
///
/// The followings arguments are needed : 
/// String target_key = Target ed25519 public key, will be stored
/// String author_ed = Author ed25519 key
/// String author_name = username of the author sent to the target
/// String author_private_ed = author private ed key, used to sign the package
pub fn request_friend(target_ed: String, author_ed: String, author_name: String, author_private_ed: String) -> [String; 3]{
    let (author_x_pub, author_x_priv) = encryption::generate_x_keys();
    let packet = format!("friend_request__{}__{}__{}__{}", author_ed, target_ed, author_x_pub, author_name);

    return [encryption::sign_packet(packet, &author_private_ed), author_x_pub, author_x_priv]
}

/// Generate a new transaction to ask a friend, 
pub fn add_friend(own_public_x: String, friend_public_x_base64: String, friend_public_ed: String, friend_username: String) -> bool {
    todo!()
}
