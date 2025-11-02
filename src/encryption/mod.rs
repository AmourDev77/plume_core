use std::{fmt, str::FromStr};
use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::{DecodePrivateKey, DecodePublicKey}, Signature, SigningKey, VerifyingKey};

pub mod keys;

pub enum TransactionError {
    UnknownKeyError()
}
/// This function will encrypt a message using the given key.
/// Key must be given in pkcs8 encoded format
pub fn sign_packet(packet: String, key: &str) -> String {
    let mut key: SigningKey = SigningKey::from_pkcs8_pem(key).expect("Invalid Signing key provided, unable to send packet");

    let signature = key.sign(packet.as_bytes());
    format!("{}__{}", packet, signature)
}


/// This function is used to encrypt the content of a message using the x25519 shared key
pub fn encrypt_payload(message: &str, sharedKey: &str) -> String {
    String::new()
}


#[derive(Debug)]
pub struct FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid format")
    }
}

impl std::error::Error for FormatError {}

/// Verify the signature of a given packet.
/// Remember, a packet will always follow same structure : 
///
/// 
/// <type_packet>--<author_ed25519>--[infos supplémentaires]--<signature_auteur>
/// 
/// So this function verify if the last data of the packet (signature so) can verify the whole rest
/// of it and return a boolean corresponding to if it succeded or not
///
/// Returns an error if the package has an invalid format (less than 3 parts separated by "__")
///
pub fn verify_packet_signature(packet: &str) -> Result<bool, FormatError> {
    let mut split_informations: Vec<&str> = packet.split("__").collect();

    if split_informations.len() < 3 {
        return Err(FormatError);
    }

    if let Ok(key) = VerifyingKey::from_public_key_pem(split_informations[1]) {
        // Now we can verify message by joining all remaining elements with -- and compare the
        // signature + key with it

        if let Ok(signature) = Signature::from_str(split_informations.pop().unwrap()) {
            let content = split_informations.join("__");
            println!("Veriying string : {content}");

            match key.verify_strict(content.as_bytes(), &signature) {
                Ok(_) => {
                    return Ok(true);
                },
                Err(_) => {
                    return Ok(false);
                }
            }
        }     

        println!("Invalid Signature format")
    } 

    println!("Invalid key : {}", &split_informations[1]);
    Ok(false)
}

#[cfg(test)]
mod tests {
    use crate::encryption::{sign_packet, verify_packet_signature};

    // TEST KEYS ONLY - NOT FOR PRODUCTION - Safe for version control
    const TEST_SECRET_FALSE: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAKjzH5wXye36XrlRyzoR8pTTn5OXOCnZw3kJb64HTtgY=
-----END PUBLIC KEY-----"#;

    const TEST_SECRET_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIM2Ktbc39QNjliTncLurqP8FpnSuBsbMGcdwC8Y4e6vg
gSEA2oJO54T5oBYTdCVxw6YVafXLkrfg8q0CLp2+28vIaXQ=
-----END PRIVATE KEY-----"#;

    const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0ifZuxA7IXpdwvnt8q4AtLXAyl3Rtp6yAV7doQwCb3g=
-----END PUBLIC KEY-----"#;

    #[test]
    fn test_invalid_signature_verification() {
        let signed_packet = sign_packet(format!("test_packet__{}", TEST_PUBLIC_KEY), TEST_SECRET_FALSE);
        println!("Packet: {}", signed_packet);
        let verification = verify_packet_signature(&signed_packet).unwrap();
        println!("Verif: {}", verification);
        assert!(!verification);
    }

    #[test]
    #[ignore = "not handled"]
    fn test_valid_verification() {
        let signed_packet = sign_packet(format!("test_packet__{}", TEST_PUBLIC_KEY), TEST_SECRET_KEY);
        println!("Packet: {}", signed_packet);
        let verification = verify_packet_signature(&signed_packet).unwrap();
        println!("Verif: {}", verification);
        assert!(verification)
    }
}
