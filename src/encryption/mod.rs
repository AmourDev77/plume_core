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


    let signature = key.try_sign(packet.as_bytes()).expect("Error signing packet");
    format!("{}__{}", packet, signature)
}


/// This function is used to encrypt the content of a message using the x25519 shared key
pub fn encrypt_payload(message: &str, sharedKey: &str) -> String {
    String::new()
}


#[derive(Debug)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid format")
    }
}

impl std::error::Error for SignatureError {}

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
pub fn verify_packet_signature(packet: &str) -> Result<bool, SignatureError> {
    let mut split_informations: Vec<&str> = packet.split("__").collect();

    if split_informations.len() < 3 {
        return Err(SignatureError);
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
    #[test]
    #[ignore = "Not implemented yet"]
    fn test_invalid_signature_verification() {
        todo!()
    }
}
