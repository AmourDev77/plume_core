use crate::config::Me;

pub fn retrieve_friend_x(target_public_ed: &str, author_signing_key: &str) -> Result<String, super::PacketGenerationError> {
    todo!("Generate a packet to ask relay to give the target public x25519 key");
}

pub fn generate_friend_request_packet(target_public_ed: &str, author_signing_key: &str, shared_key: &str, author_data: Me, author_x_public_key: &str) {
    todo!("Generate the friend request packet")
}

#[cfg(test)]
mod tests {
    mod retrieve_friend_x {
        #[test]
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
