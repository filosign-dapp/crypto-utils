use wasm_bindgen::prelude::*;
use getrandom::getrandom;
use argon2::{Argon2, Params};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}, XNonce};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroize;
use serde::Serialize;
use hex;
use p256::{
    PublicKey, 
    elliptic_curve::{
        sec1::ToEncodedPoint,
        ecdh::diffie_hellman,
    },
    SecretKey,
};
use rand_core::OsRng;

fn generate_salt_internal(buf: &mut [u8]) {
  getrandom(buf).expect("rng");
}

#[derive(Serialize)]
struct PublicKeyResult {
  public_key: String,
}

#[derive(Serialize)]
struct SaltsResult {
  pin_salt: String,
  auth_salt: String,
  wrapper_salt: String,
}

#[derive(Serialize)]
struct RegisterChallenge {
  challenge: String,
}

#[wasm_bindgen]
pub fn generate_salts() -> JsValue {
  let mut pin_salt = [0u8; 32];
  let mut auth_salt = [0u8; 32];
  let mut wrapper_salt = [0u8; 32];

  generate_salt_internal(&mut pin_salt);
  generate_salt_internal(&mut auth_salt);
  generate_salt_internal(&mut wrapper_salt);

  let salts = SaltsResult {
    pin_salt: general_purpose::STANDARD.encode(&pin_salt),
    auth_salt: general_purpose::STANDARD.encode(&auth_salt),
    wrapper_salt: general_purpose::STANDARD.encode(&wrapper_salt),
  };
  serde_wasm_bindgen::to_value(&salts).unwrap()
}

#[wasm_bindgen]
pub fn generate_nonce() -> String {
  let mut nonce = [0u8; 32];
  generate_salt_internal(&mut nonce);
  general_purpose::STANDARD.encode(&nonce)
}

#[wasm_bindgen]
pub fn generate_register_challenge(address: &str, version: &str, nonce_b64: &str) -> JsValue {
  let nonce = match general_purpose::STANDARD.decode(nonce_b64) {
    Ok(n) => n,
    Err(_) => {
      let error = serde_json::json!({"error": "Invalid base64 nonce"});
      return serde_wasm_bindgen::to_value(&error).unwrap();
    }
  };
  
  let challenge = format!("filosign:v{}:{}:{}", version, address, hex::encode(&nonce));
  let rc = RegisterChallenge {
    challenge
  };
  serde_wasm_bindgen::to_value(&rc).unwrap()
}

#[derive(Serialize)]
struct DerivationResult {
  commitment: String,
  enc_seed: String,       
  encryption_key: String, 
}

#[wasm_bindgen]
pub fn derive_encryption_material(signature_b64: &str, pin: &str, pin_salt_b64: &str, auth_salt_b64: &str, wrapper_salt_b64: &str, info: &str) -> JsValue {
  
  let pin_salt = general_purpose::STANDARD.decode(pin_salt_b64).expect("bad base64");
  let auth_salt = general_purpose::STANDARD.decode(auth_salt_b64).expect("bad base64");
  let wrapper_salt = general_purpose::STANDARD.decode(wrapper_salt_b64).expect("bad base64");
  let signature = general_purpose::STANDARD.decode(signature_b64).expect("bad base64");

  
  let mut pin_key = [0u8; 32];
  {
    
    let params = Params::new(65536, 3, 1, None).expect("params"); 
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(pin.as_bytes(), &pin_salt, &mut pin_key).expect("argon2");
  }

  
  let hk = Hkdf::<Sha256>::new(Some(&auth_salt), &signature);
  let mut auth_key = [0u8; 32];
  hk.expand(b"auth key", &mut auth_key).expect("hkdf");

  
  let mut x = [0u8; 32];
  for i in 0..32 { x[i] = auth_key[i] ^ pin_key[i]; }
  let hk2 = Hkdf::<Sha256>::new(Some(&wrapper_salt), &x);
  let mut wrapper_key = [0u8; 32];
  hk2.expand(b"wrapper key", &mut wrapper_key).expect("hkdf");

  
  let mut seed = [0u8; 32];
  generate_salt_internal(&mut seed);

  
  let mut hasher = Sha256::new();
  hasher.update(&seed);
  let commit = hasher.finalize();

  
  let aead = XChaCha20Poly1305::new(wrapper_key.as_ref().into());
  let mut nonce24 = [0u8; 24];
  generate_salt_internal(&mut nonce24);
  let nonce = XNonce::from(nonce24);
  let ciphertext = aead.encrypt(&nonce, seed.as_ref()).expect("encrypt");

  
  let hk3 = Hkdf::<Sha256>::new(None, &seed);
  let mut encryption_key = [0u8; 32];
  hk3.expand(info.as_bytes(), &mut encryption_key).expect("hkdf");

  
  auth_key.zeroize();
  pin_key.zeroize();
  x.zeroize();
  wrapper_key.zeroize();
  seed.zeroize();

  let enc_combined = [nonce24.as_ref(), ciphertext.as_ref()].concat();
  let res = DerivationResult {
    commitment: general_purpose::STANDARD.encode(&commit),
    enc_seed: general_purpose::STANDARD.encode(&enc_combined),
    encryption_key: general_purpose::STANDARD.encode(&encryption_key),
  };

  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[derive(Serialize)]
struct RegenerationResult {
  encryption_key: String, 
}

#[wasm_bindgen]
pub fn regenerate_encryption_key(
  signature_b64: &str, 
  pin: &str, 
  pin_salt_b64: &str, 
  auth_salt_b64: &str, 
  wrapper_salt_b64: &str, 
  enc_seed_b64: &str, 
  info: &str
) -> JsValue {
  
  let pin_salt = general_purpose::STANDARD.decode(pin_salt_b64).expect("bad pin_salt base64");
  let auth_salt = general_purpose::STANDARD.decode(auth_salt_b64).expect("bad auth_salt base64");
  let wrapper_salt = general_purpose::STANDARD.decode(wrapper_salt_b64).expect("bad wrapper_salt base64");
  let signature = general_purpose::STANDARD.decode(signature_b64).expect("bad signature base64");
  let enc_combined = general_purpose::STANDARD.decode(enc_seed_b64).expect("bad enc_seed base64");

  
  if enc_combined.len() < 24 {
    panic!("enc_seed too short");
  }
  let nonce24: [u8; 24] = enc_combined[0..24].try_into().expect("nonce extraction");
  let ciphertext = &enc_combined[24..];

  
  let mut pin_key = [0u8; 32];
  {
    let params = Params::new(65536, 3, 1, None).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(pin.as_bytes(), &pin_salt, &mut pin_key).expect("argon2");
  }

  
  let hk = Hkdf::<Sha256>::new(Some(&auth_salt), &signature);
  let mut auth_key = [0u8; 32];
  hk.expand(b"auth key", &mut auth_key).expect("hkdf");

  
  let mut x = [0u8; 32];
  for i in 0..32 { x[i] = auth_key[i] ^ pin_key[i]; }
  let hk2 = Hkdf::<Sha256>::new(Some(&wrapper_salt), &x);
  let mut wrapper_key = [0u8; 32];
  hk2.expand(b"wrapper key", &mut wrapper_key).expect("hkdf");

  
  let aead = XChaCha20Poly1305::new(wrapper_key.as_ref().into());
  let nonce = XNonce::from(nonce24);
  let seed = aead.decrypt(&nonce, ciphertext).expect("decrypt failed - wrong pin or corrupted data");

  
  let hk3 = Hkdf::<Sha256>::new(None, &seed);
  let mut encryption_key = [0u8; 32];
  hk3.expand(info.as_bytes(), &mut encryption_key).expect("hkdf");

  
  auth_key.zeroize();
  pin_key.zeroize();
  x.zeroize();
  wrapper_key.zeroize();

  let res = RegenerationResult {
    encryption_key: general_purpose::STANDARD.encode(&encryption_key),
  };

  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[derive(Serialize)]
struct KeyPairResult {
  private_key: String, 
  public_key: String,  
}

#[wasm_bindgen]
pub fn generate_key_pair() -> JsValue {
  
  let secret_key = SecretKey::random(&mut OsRng);
  let public_key = secret_key.public_key();
  
  
  let private_bytes = secret_key.to_bytes();
  let public_point = public_key.to_encoded_point(false); 
  let public_bytes = &public_point.as_bytes()[1..33]; 
  
  let res = KeyPairResult {
    private_key: general_purpose::STANDARD.encode(&private_bytes),
    public_key: general_purpose::STANDARD.encode(public_bytes),
  };
  
  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[derive(Serialize)]
struct SharedKeyResult {
  shared_key: String, 
}

#[wasm_bindgen]
pub fn create_shared_key(
  self_private_key_b64: &str,
  other_public_key_b64: &str
) -> JsValue {
  let private_key_bytes = general_purpose::STANDARD.decode(self_private_key_b64).expect("decode private key");
  let private_key_array: [u8; 32] = private_key_bytes.try_into().expect("private key bytes to 32 bytes");
  let private_key = SecretKey::from_bytes(&private_key_array.into()).expect("create private key");

  
  let other_public_key_bytes = general_purpose::STANDARD.decode(other_public_key_b64).expect("decode other public key");
  
  let other_public_key = if other_public_key_bytes.len() == 32 {
    
    let mut full_key = vec![0x02u8]; 
    full_key.extend_from_slice(&other_public_key_bytes);
    PublicKey::from_sec1_bytes(&full_key).expect("create public key from x-coordinate")
  } else {
    
    PublicKey::from_sec1_bytes(&other_public_key_bytes).expect("create public key")
  };
  
  
  let shared_secret = diffie_hellman(
    private_key.to_nonzero_scalar(),
    other_public_key.as_affine()
  );
  
  
  let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes());
  let mut shared_key = [0u8; 32];
  hk.expand(b"shared encryption key", &mut shared_key).expect("hkdf shared key");
  
  let res = SharedKeyResult {
    shared_key: general_purpose::STANDARD.encode(&shared_key),
  };
  
  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[wasm_bindgen]
pub fn get_public_key_from_regenerated(
  signature_b64: &str, 
  pin: &str, 
  pin_salt_b64: &str, 
  auth_salt_b64: &str, 
  wrapper_salt_b64: &str, 
  enc_seed_b64: &str, 
  cid: &str
) -> JsValue {
  
  let regen_result = regenerate_encryption_key(
    signature_b64, 
    pin, 
    pin_salt_b64, 
    auth_salt_b64, 
    wrapper_salt_b64, 
    enc_seed_b64, 
    cid
  );
  
  
  let regen_obj: serde_json::Value = serde_wasm_bindgen::from_value(regen_result).expect("parse regen result");
  let encryption_key_b64 = regen_obj["encryption_key"].as_str().expect("get encryption_key");
  let encryption_key = general_purpose::STANDARD.decode(encryption_key_b64).expect("decode encryption_key");
  
  
  let private_key_bytes: [u8; 32] = encryption_key.try_into().expect("encryption key to 32 bytes");
  let private_key = SecretKey::from_bytes(&private_key_bytes.into()).expect("create private key");
  let public_key = private_key.public_key();
  
  let public_point = public_key.to_encoded_point(false); 
  let public_x_bytes = &public_point.as_bytes()[1..33]; 
  let res = PublicKeyResult { public_key: general_purpose::STANDARD.encode(public_x_bytes) };
  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[wasm_bindgen]
pub fn generate_salt(len: u32) -> String {
  if len == 0 || len > 1024 {
    panic!("invalid salt length");
  }
  let mut buf = vec![0u8; len as usize];
  generate_salt_internal(&mut buf);
  general_purpose::STANDARD.encode(&buf)
}

#[wasm_bindgen]
pub fn to_hex(b64: &str) -> String {
  let bytes = general_purpose::STANDARD.decode(b64).expect("invalid base64");
  hex::encode(bytes)
}

#[wasm_bindgen]
pub fn to_b64(hex_str: &str) -> String {
  let cleaned_hex = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
    &hex_str[2..]
  } else {
    hex_str
  };
  let bytes = hex::decode(cleaned_hex).expect("invalid hex");
  general_purpose::STANDARD.encode(bytes)
}
