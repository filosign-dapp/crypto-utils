import * as wasm from "./pkg/filosign_crypto_utils.js";

let wasmInitialized = false;
let initPromise: Promise<void> | null = null;

export async function ensureWasmInitialized(wasmInput?: any): Promise<void> {
  if (wasmInitialized) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    if (typeof wasm.default !== "function") {
      throw new Error("WASM default export is not a function");
    }

    if (wasmInput) {
      try {
        await wasm.default(wasmInput);
        wasmInitialized = true;
        return;
      } catch (e) {
        throw new Error(`WASM initialization failed with provided input: ${e}`);
      }
    }

    const errors: string[] = [];
    const environment = {
      hasImportMeta: typeof import.meta !== "undefined",
      hasImportMetaUrl: typeof import.meta !== "undefined" && !!import.meta.url,
      // hasWindow: typeof window !== "undefined",
      hasGlobal: typeof (globalThis as any).global !== "undefined",
      hasProcess: typeof (globalThis as any).process !== "undefined",
      userAgent:
        typeof navigator !== "undefined" ? navigator.userAgent : "unknown",
    };

    try {
      let wasmBytes: ArrayBuffer | undefined;

      if (environment.hasImportMetaUrl) {
        try {
          const wasmUrl = new URL(
            "./pkg/filosign_crypto_utils_bg.wasm",
            import.meta.url
          );
          const response = await fetch(wasmUrl);
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
          wasmBytes = await response.arrayBuffer();
        } catch (e) {
          errors.push(`Manual fetch failed: ${e}`);
        }
      }

      if (wasmBytes) {
        await wasm.default(wasmBytes);
        wasmInitialized = true;
        return;
      }

      const wasmModule = await import("./pkg/filosign_crypto_utils_bg.wasm");
      await wasm.default(wasmModule);
      wasmInitialized = true;
      return;
    } catch (e) {
      errors.push(`Dynamic import failed: ${e}`);
    }

    if (environment.hasImportMetaUrl) {
      try {
        const wasmUrl = new URL(
          "./pkg/filosign_crypto_utils_bg.wasm",
          import.meta.url
        );
        await wasm.default(wasmUrl);
        wasmInitialized = true;
        return;
      } catch (e) {
        errors.push(`URL-based loading failed: ${e}`);
      }
    }

    try {
      const wasmPath = "./pkg/filosign_crypto_utils_bg.wasm";
      await wasm.default(wasmPath);
      wasmInitialized = true;
      return;
    } catch (e) {
      errors.push(`Path-based loading failed: ${e}`);
    }

    try {
      await wasm.default();
      wasmInitialized = true;
      return;
    } catch (e) {
      errors.push(`Default initialization failed: ${e}`);
    }

    const errorMessage = [
      `WASM initialization failed. All strategies failed.`,
      `Environment: ${JSON.stringify(environment, null, 2)}`,
      `Errors:\n${errors.join("\n")}`,
    ].join("\n");

    throw new Error(errorMessage);
  })();

  return initPromise;
}

// Re-export with camelCase naming for JavaScript consumers
export function getPublicKeyFromEncryptionKey(
  signatureB64: string,
  pin: string,
  pinSaltB64: string,
  authSaltB64: string,
  wrapperSaltB64: string,
  encSeedB64: string,
  cid: string
): { publicKey: string } {
  const res = wasm.get_public_key_from_regenerated(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    encSeedB64,
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
      "getPublicKeyFromEncryptionKey: invalid result shape; public_key missing"
    );
  }
  return { publicKey: public_key };
}

export interface RegisterChallengeResult {
  challenge: string;
}

export interface EncryptionMaterialResult {
  commitment: string;
  encSeed: string;
  encryptionKey: string;
}

export interface RegenerateKeyResult {
  encryptionKey: string;
}

export interface KeyPairResult {
  privateKey: string;
  publicKey: string;
}

export interface SharedKeyResult {
  sharedKey: string;
}

export interface SaltsResult {
  pinSalt: string;
  authSalt: string;
  wrapperSalt: string;
}

export function generateSalts(): SaltsResult {
  const res = wasm.generate_salts();
  if (!res || typeof res !== "object") {
    throw new Error("generateSalts: invalid result");
  }
  const result = res as any;
  return {
    pinSalt: result.pin_salt,
    authSalt: result.auth_salt,
    wrapperSalt: result.wrapper_salt,
  };
}

export function generateNonce(): string {
  return wasm.generate_nonce();
}

export function generateRegisterChallenge(
  address: string,
  version: string,
  nonceB64: string
): RegisterChallengeResult {
  const res = wasm.generate_register_challenge(address, version, nonceB64);
  if (!res || typeof res !== "object") {
    throw new Error("generateRegisterChallenge: invalid result");
  }
  const result = res as any;
  return {
    challenge: result.challenge,
  };
}

export function deriveEncryptionMaterial(
  signatureB64: string,
  pin: string,
  pinSaltB64: string,
  authSaltB64: string,
  wrapperSaltB64: string,
  info: string
): EncryptionMaterialResult {
  const res = wasm.derive_encryption_material(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    info
  );
  if (!res || typeof res !== "object") {
    throw new Error("deriveEncryptionMaterial: invalid result");
  }
  const result = res as any;
  return {
    commitment: result.commitment,
    encSeed: result.enc_seed,
    encryptionKey: result.encryption_key,
  };
}

export function regenerateEncryptionKey(
  signatureB64: string,
  pin: string,
  pinSaltB64: string,
  authSaltB64: string,
  wrapperSaltB64: string,
  encSeedB64: string,
  info: string
): RegenerateKeyResult {
  const res = wasm.regenerate_encryption_key(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    encSeedB64,
    info
  );
  if (!res || typeof res !== "object") {
    throw new Error("regenerateEncryptionKey: invalid result");
  }
  const result = res as any;
  return {
    encryptionKey: result.encryption_key,
  };
}

export function generateKeyPair(): KeyPairResult {
  const res = wasm.generate_key_pair();
  if (!res || typeof res !== "object") {
    throw new Error("generateKeyPair: invalid result");
  }
  const result = res as any;
  return {
    privateKey: result.private_key,
    publicKey: result.public_key,
  };
}

export function createSharedKey(
  selfPrivateKeyB64: string,
  otherPublicKeyB64: string
): SharedKeyResult {
  const res = wasm.create_shared_key(selfPrivateKeyB64, otherPublicKeyB64);
  if (!res || typeof res !== "object") {
    throw new Error("createSharedKey: invalid result");
  }
  const result = res as any;
  return {
    sharedKey: result.shared_key,
  };
}

export function getPublicKeyFromRegenerated(
  signatureB64: string,
  pin: string,
  pinSaltB64: string,
  authSaltB64: string,
  wrapperSaltB64: string,
  encSeedB64: string,
  cid: string
): { publicKey: string } {
  const res = wasm.get_public_key_from_regenerated(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    encSeedB64,
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
      "getPublicKeyFromRegenerated: invalid result shape; public_key missing"
    );
  }
  return { publicKey: public_key };
}

export function generateSalt(len: number): string {
  return wasm.generate_salt(len);
}

export function toHex(b64: string): string {
  return wasm.to_hex(b64);
}

export function toB64(hexStr: string): string {
  return wasm.to_b64(hexStr);
}
