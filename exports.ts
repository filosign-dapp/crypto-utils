export * from "./pkg-node/filosign_crypto_utils.js";

export interface RegisterChallengeResult {
  challenge: string;
  pin_salt: string;
  auth_salt: string;
  wrapper_salt: string;
}

export interface EncryptionMaterialResult {
  commitment: string;
  enc_seed: string;
  encryption_key: string;
}

export interface RegenerateKeyResult {
  encryption_key: string;
}

export declare function generate_register_challenge(
  address: string,
  version: string
): RegisterChallengeResult;

export declare function derive_encryption_material(
  signature_b64: string,
  pin: string,
  pin_salt_b64: string,
  auth_salt_b64: string,
  wrapper_salt_b64: string,
  cid: string
): EncryptionMaterialResult;

export declare function regenerate_encryption_key(
  signature_b64: string,
  pin: string,
  pin_salt_b64: string,
  auth_salt_b64: string,
  wrapper_salt_b64: string,
  enc_seed_b64: string,
  cid: string
): RegenerateKeyResult;
