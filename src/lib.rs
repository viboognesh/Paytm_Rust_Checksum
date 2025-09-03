use std::error::Error;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose};
use rand::{Rng, rng};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz!@#$&_";
    let mut random_rng = rng();

    (0..length)
        .map(|_| {
            let idx = random_rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn get_string_by_params(params: &Value) -> String {
    if let Value::Object(obj) = params {
        let sorted_map: BTreeMap<_, _> = obj.iter().collect();

        let sorted_values: Vec<String> = sorted_map
            .values()
            .map(|v| match v {
                Value::String(s) => {
                    if s.to_lowercase() == "null" {
                        "".to_string()
                    } else {
                        s.clone()
                    }
                }
                _ => "".to_string(),
            })
            .collect();

        sorted_values.join("|")
    } else {
        "".to_string()
    }
}

fn calculate_hash(params: &str, salt: &str) -> String {
    let final_string = format!("{}|{}", params, salt);
    let mut hasher = Sha256::new();
    hasher.update(final_string.as_bytes());
    let hash_bytes = hasher.finalize();
    let hash_string = hex::encode(hash_bytes);

    format!("{}{}", hash_string, salt)
}

fn calculate_checksum(params: &str, key: &str, salt: &str) -> Result<String, Box<dyn Error>> {
    let hash_string = calculate_hash(params, salt);
    let checksum = encrypt(&hash_string, key.as_bytes())?;
    Ok(checksum)
}

pub fn generate_signature(params: &Value, key: &str) -> Result<String, Box<dyn Error>> {
    let sorted_string = get_string_by_params(params);
    generate_signature_by_string(&sorted_string, key)
}

fn generate_signature_by_string(params: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let salt = generate_random_string(4);
    calculate_checksum(params, key, &salt)
}

fn get_new_value_without_checksum(params: &Value) -> Value {
    if let Value::Object(obj) = params {
        let mut new_obj = obj.clone();
        new_obj.remove("CHECKSUMHASH");
        Value::Object(new_obj)
    } else {
        params.clone()
    }
}

pub fn verify_signature(params: &Value, key: &str, checksum: &str) -> Result<bool, Box<dyn Error>> {
    let filtered_params = get_new_value_without_checksum(params);
    let sorted_string = get_string_by_params(&filtered_params);
    println!("{sorted_string}");
    verify_signature_by_string(&sorted_string, key, checksum)
}

fn verify_signature_by_string(
    params: &str,
    key: &str,
    checksum: &str,
) -> Result<bool, Box<dyn Error>> {
    let paytm_hash = decrypt(checksum, key.as_bytes())?;

    if paytm_hash.len() < 4 {
        return Ok(false);
    }

    let salt_start_index = paytm_hash.len() - 4;
    let salt = &paytm_hash[salt_start_index..];

    let calculated_checksum = calculate_checksum(params, key, salt)?;

    Ok(checksum == calculated_checksum)
}

fn encrypt<T>(request_body: T, merchant_key: &[u8]) -> Result<String, Box<dyn Error>>
where
    T: AsRef<[u8]>,
{
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let input_bytes: &[u8] = request_body.as_ref();
    let iv = b"@@@@&&&&####$$$$".as_ref();
    let key_bytes: &[u8] = merchant_key;

    let buf_size: usize = ((input_bytes.len() / 16) + 1) * 16;
    let mut buf = vec![0u8; buf_size];

    let ct_result = Aes128CbcEnc::new(key_bytes.into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(input_bytes, &mut buf);
    match ct_result {
        Ok(ct) => Ok(general_purpose::STANDARD.encode(ct)),

        Err(_) => Err("Failed to encrypt message".into()),
    }
}

fn decrypt<T>(encrypted_key: T, merchant_key: &[u8]) -> Result<String, Box<dyn Error>>
where
    T: AsRef<[u8]>,
{
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let input_bytes: &[u8] = encrypted_key.as_ref();
    let iv = b"@@@@&&&&####$$$$".as_ref();
    let key_bytes: &[u8] = merchant_key;

    let decoded_string = general_purpose::STANDARD.decode(input_bytes).unwrap();
    let bufsize = ((decoded_string.len() / 16) + 1) * 16;
    let mut buf = vec![0u8; bufsize];
    let pt_result = Aes128CbcDec::new(key_bytes.into(), iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(decoded_string.as_ref(), &mut buf);

    match pt_result {
        Ok(pt) => Ok(String::from_utf8(pt.to_vec())?),
        Err(_) => Err("Failed to decrypt message".into()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_signature_generator_verifier() {
        let key = "YOUR_MERCHANTKEY";
        let mut json_value: Value = serde_json::from_str(
            r#"
        {
            "MID": "YOUR_MID_HERE",
            "ORDER_ID": "YOUR_ORDER_ID_HERE"
        }
    "#,
        )
        .unwrap();

        let checksum = generate_signature(&json_value, key).unwrap();

        println!("GenerateSignature Returns: {}", checksum);

        let verification_value = verify_signature(&json_value, key, &checksum).unwrap();
        assert!(verification_value);

        if let Value::Object(ref mut obj) = json_value {
            obj.insert("CHECKSUMHASH".to_string(), json!(checksum));
        }

        let verification_value = verify_signature(&json_value, key, &checksum).unwrap();
        assert!(verification_value);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let input = "Hello".as_bytes();
        let key = "YOUR_MERCHANTKEY".as_bytes();

        let encrypted_key = encrypt(input, key).unwrap();
        assert_eq!(encrypted_key, "HhJfrnoTbF1uBaCdyUoQFA==".to_string());

        let decrypted_key = decrypt(encrypted_key, key).unwrap();
        assert_eq!(decrypted_key, String::from_utf8(input.to_vec()).unwrap());
    }
}
