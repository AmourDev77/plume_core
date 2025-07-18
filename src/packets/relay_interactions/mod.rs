use std::fs;

use crate::{config, encryption::sign_packet, packets};

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

pub fn generate_login(private_ed_key: &str, public_ed_key: &str, published_public_key: &str) -> String {
    // First get the author 
    let packet =  format!("login__{public_ed_key}__{published_public_key}");
    sign_packet(packet, private_ed_key)
}

#[cfg(test)]
mod test {
    use crate::{encryption::verify_packet_signature, init, packets::relay_interactions::generate_login};

    #[test]
    fn test_login_packet_generation() {
        let private_ed_key = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIDYl6V3dZDi6Q/waB+XyLEv2bjdnNXoas2fpaSPFm+up
gSEAiCd7Td+qdVFItJIHnRfszO9cnl+fcL/W2AIzCBuYsBE=
-----END PRIVATE KEY-----";
        let public_ed_key = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAiCd7Td+qdVFItJIHnRfszO9cnl+fcL/W2AIzCBuYsBE=
-----END PUBLIC KEY-----";

        let public_published_key = "c13re0ol2Z9o6R-nAK8Owb1gZ82t14EJ6fpUUPSwsWw=";

        let login_packet = generate_login(private_ed_key, public_ed_key, public_published_key);
        assert!(verify_packet_signature(&login_packet).unwrap());
    }
}
