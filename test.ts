import {
  generate_register_challenge,
  derive_encryption_material,
  regenerate_encryption_key,
  generate_key_pair,
  create_shared_key,
  get_public_key_from_encryption_key,
  type RegisterChallengeResult,
  type EncryptionMaterialResult,
  type RegenerateKeyResult,
  type KeyPairResult,
  type SharedKeyResult,
} from "./exports";

async function testBasicFunctionality() {
  console.log("🧪 Testing Basic FiloSign Crypto Utils...\n");

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
    return false;
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
    return false;
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
    return false;
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
      return false;
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
    return false;
  }

  console.log("🎉 Basic functionality tests passed!\n");
  return true;
}

async function testKeyExchange() {
  console.log("🔐 Testing Key Exchange Functionality...\n");

  // Setup for two users: Alice and Bob
  const aliceAddress = "0x1111111111111111";
  const bobAddress = "0x2222222222222222";
  const version = "1";

  console.log("👤 Setting up Alice's encryption material...");

  // Alice generates her challenge and derives encryption material
  const aliceChallenge = generate_register_challenge(aliceAddress, version);
  const aliceSignature = "YWxpY2Vfc2lnbmF0dXJlX2RhdGE="; // Alice's signature
  const alicePin = "1234";
  const aliceCid = "alice_cid";

  const aliceMaterial = derive_encryption_material(
    aliceSignature,
    alicePin,
    aliceChallenge.pin_salt,
    aliceChallenge.auth_salt,
    aliceChallenge.wrapper_salt,
    aliceCid
  );

  console.log("✓ Alice's commitment:", aliceMaterial.commitment);

  console.log("\n👤 Setting up Bob's encryption material...");

  // Bob generates his challenge and derives encryption material
  const bobChallenge = generate_register_challenge(bobAddress, version);
  const bobSignature = "Ym9iX3NpZ25hdHVyZV9kYXRh"; // Bob's signature
  const bobPin = "5678";
  const bobCid = "bob_cid";

  const bobMaterial = derive_encryption_material(
    bobSignature,
    bobPin,
    bobChallenge.pin_salt,
    bobChallenge.auth_salt,
    bobChallenge.wrapper_salt,
    bobCid
  );

  console.log("✓ Bob's commitment:", bobMaterial.commitment);

  console.log("\n🔑 Generating public keys from encryption keys...");

  // Alice gets her public key from her encryption material
  const alicePublicKeyResult = get_public_key_from_encryption_key(
    aliceSignature,
    alicePin,
    aliceChallenge.pin_salt,
    aliceChallenge.auth_salt,
    aliceChallenge.wrapper_salt,
    aliceMaterial.enc_seed,
    aliceCid
  );

  // Debug: Check the entire result object
  console.log("Alice's full public key result:", alicePublicKeyResult);
  console.log("Type of result:", typeof alicePublicKeyResult);

  // Bob gets his public key from his encryption material
  const bobPublicKeyResult = get_public_key_from_encryption_key(
    bobSignature,
    bobPin,
    bobChallenge.pin_salt,
    bobChallenge.auth_salt,
    bobChallenge.wrapper_salt,
    bobMaterial.enc_seed,
    bobCid
  );

  // Debug: Check the entire result object
  console.log("Bob's full public key result:", bobPublicKeyResult);
  console.log("Type of result:", typeof bobPublicKeyResult);

  console.log("✓ Alice's public key:", alicePublicKeyResult.public_key);
  console.log("✓ Bob's public key:", bobPublicKeyResult.public_key);

  // Debug: Check if public keys are valid
  if (!alicePublicKeyResult.public_key) {
    console.log("❌ Alice's public key is undefined!");
    return false;
  }
  if (!bobPublicKeyResult.public_key) {
    console.log("❌ Bob's public key is undefined!");
    return false;
  }

  console.log("\n🤝 Creating shared keys...");

  // Alice creates shared key with Bob's public key
  const aliceSharedKey = create_shared_key(
    aliceSignature,
    alicePin,
    aliceChallenge.pin_salt,
    aliceChallenge.auth_salt,
    aliceChallenge.wrapper_salt,
    aliceMaterial.enc_seed,
    aliceCid,
    bobPublicKeyResult.public_key
  );

  // Bob creates shared key with Alice's public key
  const bobSharedKey = create_shared_key(
    bobSignature,
    bobPin,
    bobChallenge.pin_salt,
    bobChallenge.auth_salt,
    bobChallenge.wrapper_salt,
    bobMaterial.enc_seed,
    bobCid,
    alicePublicKeyResult.public_key
  );

  console.log("✓ Alice's shared key:", aliceSharedKey.shared_key);
  console.log("✓ Bob's shared key:", bobSharedKey.shared_key);

  // Verify both parties computed the same shared key
  if (aliceSharedKey.shared_key === bobSharedKey.shared_key) {
    console.log(
      "✅ Key exchange successful! Both parties have the same shared key"
    );
  } else {
    console.log("❌ Key exchange failed! Shared keys don't match");
    return false;
  }

  console.log("\n🧪 Testing key exchange consistency...");

  // Test that the same inputs always produce the same shared key
  const aliceSharedKey2 = create_shared_key(
    aliceSignature,
    alicePin,
    aliceChallenge.pin_salt,
    aliceChallenge.auth_salt,
    aliceChallenge.wrapper_salt,
    aliceMaterial.enc_seed,
    aliceCid,
    bobPublicKeyResult.public_key
  );

  if (aliceSharedKey.shared_key === aliceSharedKey2.shared_key) {
    console.log("✅ Shared key generation is deterministic");
  } else {
    console.log("❌ Shared key generation is not deterministic");
    return false;
  }

  console.log(
    "\n🎯 Testing with different CIDs (should produce different shared keys)..."
  );

  const aliceSharedKeyDifferentCid = create_shared_key(
    aliceSignature,
    alicePin,
    aliceChallenge.pin_salt,
    aliceChallenge.auth_salt,
    aliceChallenge.wrapper_salt,
    aliceMaterial.enc_seed,
    "different_cid", // Different CID
    bobPublicKeyResult.public_key
  );

  if (aliceSharedKey.shared_key !== aliceSharedKeyDifferentCid.shared_key) {
    console.log(
      "✅ Different CIDs produce different shared keys (as expected)"
    );
  } else {
    console.log("❌ Different CIDs should produce different shared keys");
    return false;
  }

  console.log("\n🎉 Key exchange tests passed!\n");
  return true;
}

async function testStandaloneKeyPairs() {
  console.log("🗝️  Testing Standalone Key Pair Generation...\n");

  const keyPair1 = generate_key_pair();
  const keyPair2 = generate_key_pair();

  console.log("✓ Key Pair 1 - Private:", keyPair1.private_key);
  console.log("✓ Key Pair 1 - Public:", keyPair1.public_key);
  console.log("✓ Key Pair 2 - Private:", keyPair2.private_key);
  console.log("✓ Key Pair 2 - Public:", keyPair2.public_key);

  // Verify key pairs are different
  if (
    keyPair1.private_key !== keyPair2.private_key &&
    keyPair1.public_key !== keyPair2.public_key
  ) {
    console.log("✅ Key pairs are properly randomized\n");
    return true;
  } else {
    console.log("❌ Key pairs should be different\n");
    return false;
  }
}

async function runAllTests() {
  console.log("🚀 Running Complete FiloSign Crypto Utils Test Suite\n");
  console.log("============================================================\n");

  let allPassed = true;

  // Run basic functionality tests
  const basicTests = await testBasicFunctionality();
  allPassed = allPassed && basicTests;

  console.log("============================================================\n");

  // Run key exchange tests
  const keyExchangeTests = await testKeyExchange();
  allPassed = allPassed && keyExchangeTests;

  console.log("============================================================\n");

  // Run standalone key pair tests
  const keyPairTests = await testStandaloneKeyPairs();
  allPassed = allPassed && keyPairTests;

  console.log("============================================================");

  if (allPassed) {
    console.log("🎉 ALL TESTS PASSED SUCCESSFULLY!");
    console.log("\n📊 Test Summary:");
    console.log("✓ Challenge generation with randomization");
    console.log("✓ Encryption material derivation with randomization");
    console.log("✓ Deterministic key regeneration from encrypted seed");
    console.log("✓ Wrong PIN rejection");
    console.log("✓ CID-specific key derivation");
    console.log("✓ Public key extraction from encryption keys");
    console.log("✓ ECDH key exchange between parties");
    console.log("✓ Shared key consistency verification");
    console.log("✓ CID-specific shared key derivation");
    console.log("✓ Standalone key pair generation");
    console.log("\n💡 Ready for production use!");
  } else {
    console.log("❌ SOME TESTS FAILED!");
    process.exit(1);
  }
}

runAllTests().catch(console.error);
