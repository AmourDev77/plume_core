use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE, DecodeError, Engine};
use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey}, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::PublicKey;

pub enum TransactionError {
    UnknownKeyError()
}

/// Generate a x25519 key combinaison
///
/// returns !
/// 
/// (base64_private: String, base64_public: String)
/// 
pub fn generate_x_keys() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret); 

    let base64_public =URL_SAFE.encode(public);
    let base64_private = URL_SAFE.encode(secret);
    
    (base64_private, base64_public)
}

/// This function generate an ed25519 signingkey and an associated public key and returns their
/// PKCS#8 PEM form following this order : (private: String, public: String)
pub fn generate_ed_keys() -> (String, String) {
    let mut csprng = OsRng;

    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let encoded_private = signing_key.to_pkcs8_pem(Default::default()).expect("Failed to encode private key to PKCS#8 PEM").to_string();
    let encoded_public = verifying_key.to_public_key_pem(Default::default()).expect("Failed to encode private key to PKCS#8 PEM");

    return (encoded_private, encoded_public)
}



#[derive(Debug)]
pub enum SharedGenerationError {
    InvalidKeyError,
    DecodeError
}

// Important for the "?" to be usable when using URL_SAFE.decode
impl From<DecodeError> for SharedGenerationError {
    fn from(_: DecodeError) -> Self {
        SharedGenerationError::DecodeError
    }
}

impl From<Vec<u8>> for SharedGenerationError {
    fn from(_: Vec<u8>) -> Self {
        SharedGenerationError::InvalidKeyError
    }
}

/// Function Generate a shared key from two keys.
/// String user_private = user private x25519 key
/// Stirng target_public = user public w25519 key
pub fn generate_shared_key(user_private: &str, target_public: &str) -> Result<String, SharedGenerationError>  {
    // first unhash the two keys
    let decoded_private: [u8; 32] = URL_SAFE.decode(user_private)?.try_into()?;
    let decoded_public: [u8; 32] = URL_SAFE.decode(target_public)?.try_into()?;

    let private = x25519_dalek::StaticSecret::from(decoded_private);
    let public = x25519_dalek::PublicKey::from(decoded_public);

    let shared = private.diffie_hellman(&public);

    Ok(URL_SAFE.encode(shared))
}


// ---------- Key usage ----------

/// This function will encrypt a message using the given key.
/// Key must be given in pkcs8 encoded format
pub fn sign_packet(packet: String, key: &str) -> String {
    let mut key: SigningKey = SigningKey::from_pkcs8_pem(&key).expect("Invalid Signing key provided, unable to send packet");


    let signature = key.try_sign(packet.as_bytes()).expect("Error signing packet");
    format!("{}__{}", packet, signature)
}


/// This function is used to encrypt the content of a message using the x25519 shared key
pub fn encrypt_payload(message: &str, sharedKey: &str) -> String {
    todo!()
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
