import {
  generateRegisterChallenge,
  deriveEncryptionMaterial,
  regenerateEncryptionKey,
  generateKeyPair,
  createSharedKey,
  getPublicKeyFromEncryptionKey,
  generateSalt,
  generateSalts,
  generateNonce,
} from "./exports";

import { describe, it, expect } from "bun:test";

describe("FiloSign Crypto Utils", () => {
  describe("Basic Functionality", () => {
    it("should generate register challenge with proper randomization", () => {
      const address = "0x1234567890abcdef";
      const version = "1";

      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      const challengeResult1 = generateRegisterChallenge(
        address,
        version,
        nonce1
      );
      const challengeResult2 = generateRegisterChallenge(
        address,
        version,
        nonce2
      );

      expect(challengeResult1.challenge).toBeDefined();
      expect(challengeResult2.challenge).toBeDefined();
      expect(challengeResult1.challenge).not.toBe(challengeResult2.challenge);
    });

    it("should derive encryption material with randomization", () => {
      const signatureB64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
      const pin = "1234";
      const pinSaltB64 = "cGluX3NhbHRfZXhhbXBsZQ==";
      const authSaltB64 = "YXV0aF9zYWx0X2V4YW1wbGU=";
      const wrapperSaltB64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU=";
      const cid = "test_cid";

      const derivation1 = deriveEncryptionMaterial(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        cid
      );

      const derivation2 = deriveEncryptionMaterial(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        cid
      );

      expect(derivation1.commitment).toBeDefined();
      expect(derivation2.commitment).toBeDefined();
      expect(derivation1.commitment).not.toBe(derivation2.commitment);
    });

    it("should regenerate encryption key consistently", () => {
      const signatureB64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
      const pin = "1234";
      const pinSaltB64 = "cGluX3NhbHRfZXhhbXBsZQ==";
      const authSaltB64 = "YXV0aF9zYWx0X2V4YW1wbGU=";
      const wrapperSaltB64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU=";
      const cid = "test_cid";

      const derivation = deriveEncryptionMaterial(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        cid
      );

      const regeneratedResult1 = regenerateEncryptionKey(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        derivation.encSeed,
        cid
      );

      const regeneratedResult2 = regenerateEncryptionKey(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        derivation.encSeed,
        cid
      );

      expect(derivation.encryptionKey).toBe(regeneratedResult1.encryptionKey);
      expect(regeneratedResult1.encryptionKey).toBe(
        regeneratedResult2.encryptionKey
      );
    });

    it("should fail with wrong PIN", () => {
      const signatureB64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
      const pin = "1234";
      const wrongPin = "5678";
      const pinSaltB64 = "cGluX3NhbHRfZXhhbXBsZQ==";
      const authSaltB64 = "YXV0aF9zYWx0X2V4YW1wbGU=";
      const wrapperSaltB64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU=";
      const cid = "test_cid";

      const derivation = deriveEncryptionMaterial(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        cid
      );

      expect(() => {
        regenerateEncryptionKey(
          signatureB64,
          wrongPin,
          pinSaltB64,
          authSaltB64,
          wrapperSaltB64,
          derivation.encSeed,
          cid
        );
      }).toThrow();
    });

    it("should produce different keys with different CID", () => {
      const signatureB64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
      const pin = "1234";
      const pinSaltB64 = "cGluX3NhbHRfZXhhbXBsZQ==";
      const authSaltB64 = "YXV0aF9zYWx0X2V4YW1wbGU=";
      const wrapperSaltB64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU=";
      const cid = "test_cid";
      const differentCid = "different_cid";

      const derivation = deriveEncryptionMaterial(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        cid
      );

      const differentCidResult = regenerateEncryptionKey(
        signatureB64,
        pin,
        pinSaltB64,
        authSaltB64,
        wrapperSaltB64,
        derivation.encSeed,
        differentCid
      );

      expect(differentCidResult.encryptionKey).not.toBe(
        derivation.encryptionKey
      );
    });
  });

  describe("Key Exchange", () => {
    it("should perform successful key exchange between two parties", () => {
      const aliceAddress = "0x1111111111111111";
      const bobAddress = "0x2222222222222222";
      const version = "1";

      // Alice setup
      const aliceSalts = generateSalts();
      const aliceNonce = generateNonce();
      const aliceChallenge = generateRegisterChallenge(
        aliceAddress,
        version,
        aliceNonce
      );
      const aliceSignature = "YWxpY2Vfc2lnbmF0dXJlX2RhdGE=";
      const alicePin = "1234";
      const aliceCid = "alice_cid";

      const aliceMaterial = deriveEncryptionMaterial(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceCid
      );

      // Bob setup
      const bobSalts = generateSalts();
      const bobNonce = generateNonce();
      const bobChallenge = generateRegisterChallenge(
        bobAddress,
        version,
        bobNonce
      );
      const bobSignature = "Ym9iX3NpZ25hdHVyZV9kYXRh";
      const bobPin = "5678";
      const bobCid = "bob_cid";

      const bobMaterial = deriveEncryptionMaterial(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobCid
      );

      // Get public keys
      const alicePublicKeyResult = getPublicKeyFromEncryptionKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        aliceCid
      );

      const bobPublicKeyResult = getPublicKeyFromEncryptionKey(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobMaterial.encSeed,
        bobCid
      );

      expect(alicePublicKeyResult.publicKey).toBeDefined();
      expect(bobPublicKeyResult.publicKey).toBeDefined();

      // Create shared keys
      const aliceSharedKey = createSharedKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        aliceCid,
        bobPublicKeyResult.publicKey
      );

      const bobSharedKey = createSharedKey(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobMaterial.encSeed,
        bobCid,
        alicePublicKeyResult.publicKey
      );

      expect(aliceSharedKey.sharedKey).toBe(bobSharedKey.sharedKey);
    });

    it("should produce consistent shared keys", () => {
      const aliceAddress = "0x1111111111111111";
      const bobAddress = "0x2222222222222222";
      const version = "1";

      // Setup (simplified for consistency test)
      const aliceSalts = generateSalts();
      const aliceNonce = generateNonce();
      const aliceChallenge = generateRegisterChallenge(
        aliceAddress,
        version,
        aliceNonce
      );
      const aliceSignature = "YWxpY2Vfc2lnbmF0dXJlX2RhdGE=";
      const alicePin = "1234";
      const aliceCid = "alice_cid";

      const aliceMaterial = deriveEncryptionMaterial(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceCid
      );

      const bobSalts = generateSalts();
      const bobNonce = generateNonce();
      const bobChallenge = generateRegisterChallenge(
        bobAddress,
        version,
        bobNonce
      );
      const bobSignature = "Ym9iX3NpZ25hdHVyZV9kYXRh";
      const bobPin = "5678";
      const bobCid = "bob_cid";

      const bobMaterial = deriveEncryptionMaterial(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobCid
      );

      const bobPublicKeyResult = getPublicKeyFromEncryptionKey(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobMaterial.encSeed,
        bobCid
      );

      // Test that the same inputs always produce the same shared key
      const aliceSharedKey1 = createSharedKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        aliceCid,
        bobPublicKeyResult.publicKey
      );

      const aliceSharedKey2 = createSharedKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        aliceCid,
        bobPublicKeyResult.publicKey
      );

      expect(aliceSharedKey1.sharedKey).toBe(aliceSharedKey2.sharedKey);
    });

    it("should produce different shared keys with different CIDs", () => {
      const aliceAddress = "0x1111111111111111";
      const bobAddress = "0x2222222222222222";
      const version = "1";

      // Setup (simplified)
      const aliceSalts = generateSalts();
      const aliceNonce = generateNonce();
      const aliceChallenge = generateRegisterChallenge(
        aliceAddress,
        version,
        aliceNonce
      );
      const aliceSignature = "YWxpY2Vfc2lnbmF0dXJlX2RhdGE=";
      const alicePin = "1234";
      const aliceCid = "alice_cid";

      const aliceMaterial = deriveEncryptionMaterial(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceCid
      );

      const bobSalts = generateSalts();
      const bobNonce = generateNonce();
      const bobChallenge = generateRegisterChallenge(
        bobAddress,
        version,
        bobNonce
      );
      const bobSignature = "Ym9iX3NpZ25hdHVyZV9kYXRh";
      const bobPin = "5678";
      const bobCid = "bob_cid";

      const bobMaterial = deriveEncryptionMaterial(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobCid
      );

      const bobPublicKeyResult = getPublicKeyFromEncryptionKey(
        bobSignature,
        bobPin,
        bobSalts.pinSalt,
        bobSalts.authSalt,
        bobSalts.wrapperSalt,
        bobMaterial.encSeed,
        bobCid
      );

      const aliceSharedKey = createSharedKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        aliceCid,
        bobPublicKeyResult.publicKey
      );

      const aliceSharedKeyDifferentCid = createSharedKey(
        aliceSignature,
        alicePin,
        aliceSalts.pinSalt,
        aliceSalts.authSalt,
        aliceSalts.wrapperSalt,
        aliceMaterial.encSeed,
        "different_cid",
        bobPublicKeyResult.publicKey
      );

      expect(aliceSharedKey.sharedKey).not.toBe(
        aliceSharedKeyDifferentCid.sharedKey
      );
    });
  });

  describe("Key Pair Generation", () => {
    it("should generate unique key pairs", () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();

      expect(keyPair1.privateKey).toBeDefined();
      expect(keyPair1.publicKey).toBeDefined();
      expect(keyPair2.privateKey).toBeDefined();
      expect(keyPair2.publicKey).toBeDefined();

      expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
      expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
    });
  });

  describe("Salt Generation", () => {
    it("should generate salts of correct length", () => {
      const s16 = generateSalt(16);
      const s32 = generateSalt(32);

      expect(typeof s16).toBe("string");
      expect(typeof s32).toBe("string");

      const b16 = Buffer.from(s16, "base64");
      const b32 = Buffer.from(s32, "base64");

      expect(b16.length).toBe(16);
      expect(b32.length).toBe(32);
    });

    it("should generate random salts", () => {
      const s1 = generateSalt(16);
      const s2 = generateSalt(16);

      expect(s1).not.toBe(s2);
    });

    it("should throw error for invalid salt length", () => {
      expect(() => generateSalt(0)).toThrow();
      expect(() => generateSalt(1025)).toThrow();
    });

    it("should generate salt sets correctly", () => {
      const salts1 = generateSalts();
      const salts2 = generateSalts();

      expect(salts1.pinSalt).toBeDefined();
      expect(salts1.authSalt).toBeDefined();
      expect(salts1.wrapperSalt).toBeDefined();

      expect(salts1.pinSalt).not.toBe(salts2.pinSalt);
      expect(salts1.authSalt).not.toBe(salts2.authSalt);
      expect(salts1.wrapperSalt).not.toBe(salts2.wrapperSalt);
    });
  });

  describe("Nonce Generation", () => {
    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      expect(typeof nonce1).toBe("string");
      expect(typeof nonce2).toBe("string");
      expect(nonce1).not.toBe(nonce2);

      const b1 = Buffer.from(nonce1, "base64");
      expect(b1.length).toBe(32);
    });
  });
});
