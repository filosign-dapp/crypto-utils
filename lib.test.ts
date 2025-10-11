import cryptoUtils from "./src/impl/node";
const {
  generateRandomHex,
  deriveEncryptionMaterial,
  regenerateEncryptionKey,
  generateKeyPair,
  createSharedKey,
  getPublicKeyFromRegenerated } = cryptoUtils;

import { describe, it, expect } from "bun:test";

describe("FiloSign Crypto Utils", () => {
  describe("Basic Functionality", () => {
    it("should generate random hex", async () => {
      const res1 = await generateRandomHex();
      const res2 = await generateRandomHex();

      expect(res1).toBeDefined();
      expect(res2).toBeDefined();
      expect(res1).not.toBe(res2);
      if (res1.ok && res2.ok) {
        expect(res1.value.startsWith("0x")).toBe(true);
        expect(res1.value.length).toBe(66); // 0x + 64 hex chars
        expect(res2.value.startsWith("0x")).toBe(true);
        expect(res2.value.length).toBe(66);
      }
    });

    it("should derive encryption material with randomization", async () => {
      const signatureHex = "74657374207369676e61747572652064617461";
      const pin = "1234";
      const pinSaltHex = "70696e5f73616c745f6578616d706c65";
      const authSaltHex = "617574685f73616c745f6578616d706c65";
      const wrapperSaltHex = "777261707065725f73616c745f6578616d706c65";
      const infoHex = "746573745f636964";

      const res1 = await deriveEncryptionMaterial(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        infoHex
      );

      const res2 = await deriveEncryptionMaterial(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        infoHex
      );

      expect(res1.ok).toBe(true);
      expect(res2.ok).toBe(true);
      if (res1.ok && res2.ok) {
        expect(res1.value.commitment).toBeDefined();
        expect(res2.value.commitment).toBeDefined();
        expect(res1.value.commitment).not.toBe(res2.value.commitment);
      }
    });

    it("should regenerate encryption key consistently", async () => {
      const signatureHex = "74657374207369676e61747572652064617461";
      const pin = "1234";
      const pinSaltHex = "70696e5f73616c745f6578616d706c65";
      const authSaltHex = "617574685f73616c745f6578616d706c65";
      const wrapperSaltHex = "777261707065725f73616c745f6578616d706c65";
      const infoHex = "746573745f636964";

      const derivationRes = await deriveEncryptionMaterial(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        infoHex
      );

      expect(derivationRes.ok).toBe(true);
      if (!derivationRes.ok) return;

      const regeneratedResult1 = await regenerateEncryptionKey(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        derivationRes.value.enc_seed,
        infoHex
      );

      const regeneratedResult2 = await regenerateEncryptionKey(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        derivationRes.value.enc_seed,
        infoHex
      );

      expect(regeneratedResult1.ok).toBe(true);
      expect(regeneratedResult2.ok).toBe(true);
      if (regeneratedResult1.ok && regeneratedResult2.ok) {
        expect(derivationRes.value.encryption_key).toBe(regeneratedResult1.value.encryption_key);
        expect(regeneratedResult1.value.encryption_key).toBe(regeneratedResult2.value.encryption_key);
      }
    });

    it("should fail with wrong PIN", async () => {
      const signatureHex = "74657374207369676e61747572652064617461";
      const pin = "1234";
      const wrongPin = "5678";
      const pinSaltHex = "70696e5f73616c745f6578616d706c65";
      const authSaltHex = "617574685f73616c745f6578616d706c65";
      const wrapperSaltHex = "777261707065725f73616c745f6578616d706c65";
      const infoHex = "746573745f636964";

      const derivationRes = await deriveEncryptionMaterial(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        infoHex
      );

      expect(derivationRes.ok).toBe(true);
      if (!derivationRes.ok) return;

      const result = await regenerateEncryptionKey(
        signatureHex,
        wrongPin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        derivationRes.value.enc_seed,
        infoHex
      );

      expect(result.ok).toBe(false);
    });

    it("should produce different keys with different info", async () => {
      const signatureHex = "74657374207369676e61747572652064617461";
      const pin = "1234";
      const pinSaltHex = "70696e5f73616c745f6578616d706c65";
      const authSaltHex = "617574685f73616c745f6578616d706c65";
      const wrapperSaltHex = "777261707065725f73616c745f6578616d706c65";
      const infoHex = "746573745f636964";
      const differentInfoHex = "646966666572656e745f636964";

      const derivationRes = await deriveEncryptionMaterial(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        infoHex
      );

      expect(derivationRes.ok).toBe(true);
      if (!derivationRes.ok) return;

      const differentInfoResult = await regenerateEncryptionKey(
        signatureHex,
        pin,
        pinSaltHex,
        authSaltHex,
        wrapperSaltHex,
        derivationRes.value.enc_seed,
        differentInfoHex
      );

      expect(differentInfoResult.ok).toBe(true);
      if (differentInfoResult.ok) {
        expect(differentInfoResult.value.encryption_key).not.toBe(derivationRes.value.encryption_key);
      }
    });
  });

  describe("Key Exchange", () => {
    it("should perform successful key exchange between two parties", async () => {
      const aliceKeyPairRes = await generateKeyPair();
      const bobKeyPairRes = await generateKeyPair();

      expect(aliceKeyPairRes.ok).toBe(true);
      expect(bobKeyPairRes.ok).toBe(true);
      if (!aliceKeyPairRes.ok || !bobKeyPairRes.ok) return;

      // Alice computes shared key using her private and Bob's public
      const aliceSharedKey = await createSharedKey(
        aliceKeyPairRes.value.private_key,
        bobKeyPairRes.value.public_key
      );

      // Bob computes shared key using his private and Alice's public
      const bobSharedKey = await createSharedKey(
        bobKeyPairRes.value.private_key,
        aliceKeyPairRes.value.public_key
      );

      expect(aliceSharedKey.ok).toBe(true);
      expect(bobSharedKey.ok).toBe(true);
      if (aliceSharedKey.ok && bobSharedKey.ok) {
        expect(aliceSharedKey.value.shared_key).toBe(bobSharedKey.value.shared_key);
      }
    });

    it("should produce consistent shared keys", async () => {
      const aliceKeyPairResult = await generateKeyPair();
      const bobKeyPairResult = await generateKeyPair();

      expect(aliceKeyPairResult.ok).toBe(true);
      expect(bobKeyPairResult.ok).toBe(true);

      if (aliceKeyPairResult.ok && bobKeyPairResult.ok) {
        // Test that the same inputs always produce the same shared key
        const aliceSharedKey1 = await createSharedKey(
          aliceKeyPairResult.value.private_key,
          bobKeyPairResult.value.public_key
        );

        const aliceSharedKey2 = await createSharedKey(
          aliceKeyPairResult.value.private_key,
          bobKeyPairResult.value.public_key
        );

        expect(aliceSharedKey1.ok).toBe(true);
        expect(aliceSharedKey2.ok).toBe(true);
        if (aliceSharedKey1.ok && aliceSharedKey2.ok) {
          expect(aliceSharedKey1.value.shared_key).toBe(aliceSharedKey2.value.shared_key);
        }
      }
    });
  });

  describe("Key Pair Generation", () => {
    it("should generate unique key pairs", async () => {
      const keyPair1Result = await generateKeyPair();
      const keyPair2Result = await generateKeyPair();

      expect(keyPair1Result.ok).toBe(true);
      expect(keyPair2Result.ok).toBe(true);

      if (keyPair1Result.ok && keyPair2Result.ok) {
        expect(keyPair1Result.value.private_key).toBeDefined();
        expect(keyPair1Result.value.public_key).toBeDefined();
        expect(keyPair2Result.value.private_key).toBeDefined();
        expect(keyPair2Result.value.public_key).toBeDefined();

        expect(keyPair1Result.value.private_key).not.toBe(keyPair2Result.value.private_key);
        expect(keyPair1Result.value.public_key).not.toBe(keyPair2Result.value.public_key);
      }
    });
  });

});
