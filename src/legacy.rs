use wasm_bindgen::prelude::*;
use getrandom::getrandom;
use argon2::{Argon2, Params};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}, XNonce, Key};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroize;
use serde::Serialize;

#[derive(Serialize)]
struct RegisterChallenge {
  challenge: String,
  nonce: String,
  pin_salt: String,
  auth_salt: String,
  wrapper_salt: String,
}

#[wasm_bindgen]
pub fn generate_register_challenge(address: &str, version: &str) -> JsValue {
  
  let mut nonce = [0u8; 16];
  let mut pin_salt = [0u8; 16];
  let mut auth_salt = [0u8; 16];
  let mut wrapper_salt = [0u8; 16];

  getrandom(&mut nonce).expect("rng");
  getrandom(&mut pin_salt).expect("rng");
  getrandom(&mut auth_salt).expect("rng");
  getrandom(&mut wrapper_salt).expect("rng");

  let challenge = format!("filosign:v{}:{}:{}", version, address, hex::encode(nonce));
  let rc = RegisterChallenge {
    challenge,
    nonce: general_purpose::STANDARD.encode(&nonce),
    pin_salt: general_purpose::STANDARD.encode(&pin_salt),
    auth_salt: general_purpose::STANDARD.encode(&auth_salt),
    wrapper_salt: general_purpose::STANDARD.encode(&wrapper_salt),
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
pub fn derive_encryption_material(signature_b64: &str, pin: &str, pin_salt_b64: &str, auth_salt_b64: &str, wrapper_salt_b64: &str, cid: &str) -> JsValue {
  
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
  getrandom(&mut seed).expect("rng");

  
  let mut hasher = Sha256::new();
  hasher.update(&seed);
  let commit = hasher.finalize();

  
  let aead = XChaCha20Poly1305::new(&Key::try_from(wrapper_key.as_slice()).expect("key"));
  let mut nonce24 = [0u8; 24];
  getrandom(&mut nonce24).expect("rng");
  let nonce = XNonce::try_from(nonce24.as_slice()).expect("nonce");
  let ciphertext = aead.encrypt(&nonce, seed.as_ref()).expect("encrypt");

  
  let hk3 = Hkdf::<Sha256>::new(None, &seed);
  let mut encryption_key = [0u8; 32];
  hk3.expand(cid.as_bytes(), &mut encryption_key).expect("hkdf");

  
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
