use wasm_bindgen::prelude::*;
use getrandom::getrandom;
use argon2::{Argon2, Params};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}, XNonce};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroize;
use serde::Serialize;
use p256::{
    PublicKey, 
    elliptic_curve::{
        sec1::ToEncodedPoint,
        ecdh::diffie_hellman,
    },
    SecretKey,
};
use rand_core::OsRng;

#[derive(Serialize)]
struct PublicKeyResult {
  public_key: String,
}

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
  // 16 byte nonce/salts
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
  enc_seed: String,       // nonce || ciphertext base64
  encryption_key: String, // base64
}

#[wasm_bindgen]
pub fn derive_encryption_material(signature_b64: &str, pin: &str, pin_salt_b64: &str, auth_salt_b64: &str, wrapper_salt_b64: &str, cid: &str) -> JsValue {
  // decode inputs
  let pin_salt = general_purpose::STANDARD.decode(pin_salt_b64).expect("bad base64");
  let auth_salt = general_purpose::STANDARD.decode(auth_salt_b64).expect("bad base64");
  let wrapper_salt = general_purpose::STANDARD.decode(wrapper_salt_b64).expect("bad base64");
  let signature = general_purpose::STANDARD.decode(signature_b64).expect("bad base64");

  // 1) pin_key = Argon2id(pin, pin_salt) -> 32 bytes
  let mut pin_key = [0u8; 32];
  {
    // params: memory_kib, time_cost, parallelism
    let params = Params::new(65536, 3, 1, None).expect("params"); // 64MiB, 3 iterations
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(pin.as_bytes(), &pin_salt, &mut pin_key).expect("argon2");
  }

  // 2) auth_key = HKDF(signature, auth_salt)
  let hk = Hkdf::<Sha256>::new(Some(&auth_salt), &signature);
  let mut auth_key = [0u8; 32];
  hk.expand(b"auth key", &mut auth_key).expect("hkdf");

  // 3) wrapper_key = HKDF(auth_key XOR pin_key, wrapper_salt)
  let mut x = [0u8; 32];
  for i in 0..32 { x[i] = auth_key[i] ^ pin_key[i]; }
  let hk2 = Hkdf::<Sha256>::new(Some(&wrapper_salt), &x);
  let mut wrapper_key = [0u8; 32];
  hk2.expand(b"wrapper key", &mut wrapper_key).expect("hkdf");

  // 4) seed = random(32)
  let mut seed = [0u8; 32];
  getrandom(&mut seed).expect("rng");

  // 5) commitment = SHA256(seed)
  let mut hasher = Sha256::new();
  hasher.update(&seed);
  let commit = hasher.finalize();

  // 6) enc_seed = XChaCha20Poly1305(wrapper_key).encrypt(nonce24, seed)
  let aead = XChaCha20Poly1305::new(wrapper_key.as_ref().into());
  let mut nonce24 = [0u8; 24];
  getrandom(&mut nonce24).expect("rng");
  let nonce = XNonce::from(nonce24);
  let ciphertext = aead.encrypt(&nonce, seed.as_ref()).expect("encrypt");

  // 7) encryption_key = HKDF(seed, cid)
  let hk3 = Hkdf::<Sha256>::new(None, &seed);
  let mut encryption_key = [0u8; 32];
  hk3.expand(cid.as_bytes(), &mut encryption_key).expect("hkdf");

  // zero secrets
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
  encryption_key: String, // base64
}

#[wasm_bindgen]
pub fn regenerate_encryption_key(
  signature_b64: &str, 
  pin: &str, 
  pin_salt_b64: &str, 
  auth_salt_b64: &str, 
  wrapper_salt_b64: &str, 
  enc_seed_b64: &str, 
  cid: &str
) -> JsValue {
  // decode inputs
  let pin_salt = general_purpose::STANDARD.decode(pin_salt_b64).expect("bad pin_salt base64");
  let auth_salt = general_purpose::STANDARD.decode(auth_salt_b64).expect("bad auth_salt base64");
  let wrapper_salt = general_purpose::STANDARD.decode(wrapper_salt_b64).expect("bad wrapper_salt base64");
  let signature = general_purpose::STANDARD.decode(signature_b64).expect("bad signature base64");
  let enc_combined = general_purpose::STANDARD.decode(enc_seed_b64).expect("bad enc_seed base64");

  // extract nonce and ciphertext from enc_seed
  if enc_combined.len() < 24 {
    panic!("enc_seed too short");
  }
  let nonce24: [u8; 24] = enc_combined[0..24].try_into().expect("nonce extraction");
  let ciphertext = &enc_combined[24..];

  // 1) pin_key = Argon2id(pin, pin_salt) -> 32 bytes
  let mut pin_key = [0u8; 32];
  {
    let params = Params::new(65536, 3, 1, None).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(pin.as_bytes(), &pin_salt, &mut pin_key).expect("argon2");
  }

  // 2) auth_key = HKDF(signature, auth_salt)
  let hk = Hkdf::<Sha256>::new(Some(&auth_salt), &signature);
  let mut auth_key = [0u8; 32];
  hk.expand(b"auth key", &mut auth_key).expect("hkdf");

  // 3) wrapper_key = HKDF(auth_key XOR pin_key, wrapper_salt)
  let mut x = [0u8; 32];
  for i in 0..32 { x[i] = auth_key[i] ^ pin_key[i]; }
  let hk2 = Hkdf::<Sha256>::new(Some(&wrapper_salt), &x);
  let mut wrapper_key = [0u8; 32];
  hk2.expand(b"wrapper key", &mut wrapper_key).expect("hkdf");

  // 4) decrypt the seed using wrapper_key
  let aead = XChaCha20Poly1305::new(wrapper_key.as_ref().into());
  let nonce = XNonce::from(nonce24);
  let seed = aead.decrypt(&nonce, ciphertext).expect("decrypt failed - wrong pin or corrupted data");

  // 5) encryption_key = HKDF(seed, cid)
  let hk3 = Hkdf::<Sha256>::new(None, &seed);
  let mut encryption_key = [0u8; 32];
  hk3.expand(cid.as_bytes(), &mut encryption_key).expect("hkdf");

  // zero secrets
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
  private_key: String, // base64 encoded private key (32 bytes)
  public_key: String,  // base64 encoded compressed public key (33 bytes)
}

#[wasm_bindgen]
pub fn generate_key_pair() -> JsValue {
  // Generate a secret key instead of ephemeral secret
  let secret_key = SecretKey::random(&mut OsRng);
  let public_key = secret_key.public_key();
  
  // Convert to bytes
  let private_bytes = secret_key.to_bytes();
  let public_point = public_key.to_encoded_point(true); // compressed format
  let public_bytes = public_point.as_bytes();
  
  let res = KeyPairResult {
    private_key: general_purpose::STANDARD.encode(&private_bytes),
    public_key: general_purpose::STANDARD.encode(public_bytes),
  };
  
  serde_wasm_bindgen::to_value(&res).unwrap()
}

#[derive(Serialize)]
struct SharedKeyResult {
  shared_key: String, // base64 encoded shared key (32 bytes)
}

#[wasm_bindgen]
pub fn create_shared_key(
  signature_b64: &str, 
  pin: &str, 
  pin_salt_b64: &str, 
  auth_salt_b64: &str, 
  wrapper_salt_b64: &str, 
  enc_seed_b64: &str, 
  cid: &str,
  other_public_key_b64: &str
) -> JsValue {
  // First, regenerate our encryption key (this becomes our private key material)
  let regen_result = regenerate_encryption_key(
    signature_b64, 
    pin, 
    pin_salt_b64, 
    auth_salt_b64, 
    wrapper_salt_b64, 
    enc_seed_b64, 
    cid
  );
  
  // Extract the encryption key from the result
  let regen_obj: serde_json::Value = serde_wasm_bindgen::from_value(regen_result).expect("parse regen result");
  let encryption_key_b64 = regen_obj["encryption_key"].as_str().expect("get encryption_key");
  let encryption_key = general_purpose::STANDARD.decode(encryption_key_b64).expect("decode encryption_key");
  
  // Use the encryption key as private key material for ECDH
  let private_key_bytes: [u8; 32] = encryption_key.try_into().expect("encryption key to 32 bytes");
  let private_key = SecretKey::from_bytes(&private_key_bytes.into()).expect("create private key");
  
  // Decode the other party's public key
  let other_public_key_bytes = general_purpose::STANDARD.decode(other_public_key_b64).expect("decode other public key");
  let other_public_key = PublicKey::from_sec1_bytes(&other_public_key_bytes).expect("create public key");
  
  // Perform ECDH to get shared secret
  let shared_secret = diffie_hellman(
    private_key.to_nonzero_scalar(),
    other_public_key.as_affine()
  );
  
  // Derive a proper shared key using HKDF
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
  // Regenerate our encryption key
  let regen_result = regenerate_encryption_key(
    signature_b64, 
    pin, 
    pin_salt_b64, 
    auth_salt_b64, 
    wrapper_salt_b64, 
    enc_seed_b64, 
    cid
  );
  
  // Extract the encryption key from the result
  let regen_obj: serde_json::Value = serde_wasm_bindgen::from_value(regen_result).expect("parse regen result");
  let encryption_key_b64 = regen_obj["encryption_key"].as_str().expect("get encryption_key");
  let encryption_key = general_purpose::STANDARD.decode(encryption_key_b64).expect("decode encryption_key");
  
  // Use the encryption key as private key material
  let private_key_bytes: [u8; 32] = encryption_key.try_into().expect("encryption key to 32 bytes");
  let private_key = SecretKey::from_bytes(&private_key_bytes.into()).expect("create private key");
  let public_key = private_key.public_key();
  
  let public_point = public_key.to_encoded_point(true); // compressed format
  let res = PublicKeyResult { public_key: general_purpose::STANDARD.encode(public_point.as_bytes()) };
  serde_wasm_bindgen::to_value(&res).unwrap()
}
