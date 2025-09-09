export * from "./pkg-node/filosign_crypto_utils.js";
import * as wasm from "./pkg-node/filosign_crypto_utils.js";

// Re-export with better naming but normalize return shape to a plain object
export function get_public_key_from_encryption_key(
  signature_b64: string,
  pin: string,
  pin_salt_b64: string,
  auth_salt_b64: string,
  wrapper_salt_b64: string,
  enc_seed_b64: string,
  cid: string
): { public_key: string } {
  const res = wasm.get_public_key_from_regenerated(
    signature_b64,
    pin,
    pin_salt_b64,
    auth_salt_b64,
    wrapper_salt_b64,
    enc_seed_b64,
    cid
  );
  let public_key: unknown = undefined;
  if (res && typeof res === "object") {
    if (res instanceof Map) {
      public_key = res.get("public_key");
    } else if ("public_key" in (res as any)) {
      public_key = (res as any).public_key;
    }
  }
  if (typeof public_key !== "string") {
    throw new Error(
      "get_public_key_from_encryption_key: invalid result shape; public_key missing"
    );
  }
  return { public_key };
}

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

export interface KeyPairResult {
  private_key: string;
  public_key: string;
}

export interface SharedKeyResult {
  shared_key: string;
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

export declare function generate_key_pair(): KeyPairResult;

export declare function create_shared_key(
  signature_b64: string,
  pin: string,
  pin_salt_b64: string,
  auth_salt_b64: string,
  wrapper_salt_b64: string,
  enc_seed_b64: string,
  cid: string,
  other_public_key_b64: string
): SharedKeyResult;

export declare function get_public_key_from_regenerated(
  signature_b64: string,
  pin: string,
  pin_salt_b64: string,
  auth_salt_b64: string,
  wrapper_salt_b64: string,
  enc_seed_b64: string,
  cid: string
): { public_key: string };
