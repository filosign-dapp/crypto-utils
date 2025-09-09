import {
  generate_register_challenge,
  derive_encryption_material,
  regenerate_encryption_key,
  type RegisterChallengeResult,
  type EncryptionMaterialResult,
  type RegenerateKeyResult,
} from "./exports";

async function test() {
  console.log("🧪 Testing FiloSign Crypto Utils...\n");

  // Test 1: Generate register challenge
  console.log("📝 Test 1: Generate register challenge");
  const address = "0x1234567890abcdef";
  const version = "1";

  const challengeResult1 = generate_register_challenge(address, version);
  const challengeResult2 = generate_register_challenge(address, version);

  console.log("✓ Challenge 1:", challengeResult1.challenge);
  console.log("✓ Challenge 2:", challengeResult2.challenge);

  // Verify challenges are different (due to random nonces)
  if (challengeResult1.challenge !== challengeResult2.challenge) {
    console.log("✅ Challenges are properly randomized\n");
  } else {
    console.log("❌ Challenges should be different\n");
    return;
  }

  // Test 2: Derive encryption material with deterministic outputs
  console.log("🔐 Test 2: Derive encryption material");
  const signatureB64 = "dGVzdCBzaWduYXR1cmUgZGF0YQ==";
  const pin = "1234";
  const pinSaltB64 = "cGluX3NhbHRfZXhhbXBsZQ=="; // Fixed salt for testing
  const authSaltB64 = "YXV0aF9zYWx0X2V4YW1wbGU="; // Fixed salt for testing
  const wrapperSaltB64 = "d3JhcHBlcl9zYWx0X2V4YW1wbGU="; // Fixed salt for testing
  const cid = "test_cid";

  // First derivation
  const derivation1 = derive_encryption_material(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    cid
  );

  // Second derivation with same inputs (should produce different results due to random seed)
  const derivation2 = derive_encryption_material(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    cid
  );

  console.log("✓ Derivation 1 commitment:", derivation1.commitment);
  console.log("✓ Derivation 2 commitment:", derivation2.commitment);

  // Verify derivations are different (due to random seed)
  if (derivation1.commitment !== derivation2.commitment) {
    console.log("✅ Derivations are properly randomized\n");
  } else {
    console.log("❌ Derivations should be different\n");
    return;
  }

  // Test 3: Regenerate encryption key from encrypted seed
  console.log("🔑 Test 3: Regenerate encryption key from encrypted seed");

  const regeneratedResult1 = regenerate_encryption_key(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    derivation1.enc_seed,
    cid
  );

  const regeneratedResult2 = regenerate_encryption_key(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    derivation1.enc_seed,
    cid
  );

  console.log("✓ Original encryption key:", derivation1.encryption_key);
  console.log("✓ Regenerated key 1:", regeneratedResult1.encryption_key);
  console.log("✓ Regenerated key 2:", regeneratedResult2.encryption_key);

  // Verify regenerated keys match original and each other
  if (
    derivation1.encryption_key === regeneratedResult1.encryption_key &&
    regeneratedResult1.encryption_key === regeneratedResult2.encryption_key
  ) {
    console.log("✅ Encryption key regeneration works correctly\n");
  } else {
    console.log("❌ Encryption key regeneration failed\n");
    return;
  }

  // Test 4: Test with wrong PIN (should produce different key)
  console.log("🚫 Test 4: Test with wrong PIN");

  const wrongPin = "5678";
  try {
    const wrongKeyResult = regenerate_encryption_key(
      signatureB64,
      wrongPin,
      pinSaltB64,
      authSaltB64,
      wrapperSaltB64,
      derivation1.enc_seed,
      cid
    );

    if (wrongKeyResult.encryption_key !== derivation1.encryption_key) {
      console.log("✅ Wrong PIN produces different key (as expected)\n");
    } else {
      console.log("❌ Wrong PIN should produce different key\n");
      return;
    }
  } catch (error) {
    console.log("✅ Wrong PIN caused decryption failure (as expected)\n");
  }

  // Test 5: Test with different CID
  console.log("🎯 Test 5: Test with different CID");

  const differentCid = "different_cid";
  const differentCidResult = regenerate_encryption_key(
    signatureB64,
    pin,
    pinSaltB64,
    authSaltB64,
    wrapperSaltB64,
    derivation1.enc_seed,
    differentCid
  );

  if (differentCidResult.encryption_key !== derivation1.encryption_key) {
    console.log(
      "✅ Different CID produces different encryption key (as expected)\n"
    );
  } else {
    console.log("❌ Different CID should produce different encryption key\n");
    return;
  }

  console.log("🎉 All tests passed successfully!");
  console.log("\n📊 Test Summary:");
  console.log("✓ Challenge generation with randomization");
  console.log("✓ Encryption material derivation with randomization");
  console.log("✓ Deterministic key regeneration from encrypted seed");
  console.log("✓ Wrong PIN rejection");
  console.log("✓ CID-specific key derivation");
}

test().catch(console.error);
