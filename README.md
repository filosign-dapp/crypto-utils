# FiloSign Crypto Utils

WebAssembly-based cryptographic utilties designed specificlay for FiloSign.

## Installation

### From GitHub (for development)

```bash
bun add git+https://github.com/filosign-dapp/crypto-utils.git
```

## Usage

```typescript
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
} from "filosign-crypto-utils";

// Generate a registration challenge
const challenge = generate_register_challenge("0x1234...", "1");

// Derive encryption material
const material = derive_encryption_material(
  signatureB64,
  pin,
  challenge.pin_salt,
  challenge.auth_salt,
  challenge.wrapper_salt,
  cid
);

// Regenerate encryption key
const key = regenerate_encryption_key(
  signatureB64,
  pin,
  challenge.pin_salt,
  challenge.auth_salt,
  challenge.wrapper_salt,
  material.enc_seed,
  cid
);

// Get public key from encryption material (for key exchange)
const publicKeyResult = get_public_key_from_encryption_key(
  signatureB64,
  pin,
  challenge.pin_salt,
  challenge.auth_salt,
  challenge.wrapper_salt,
  material.enc_seed,
  cid
);

// Create shared key with another party's public key
const sharedKey = create_shared_key(
  signatureB64,
  pin,
  challenge.pin_salt,
  challenge.auth_salt,
  challenge.wrapper_salt,
  material.enc_seed,
  cid,
  otherPartyPublicKey
);

// Generate standalone key pairs (optional)
const keyPair = generate_key_pair();
```

## API

### Core Functions

#### `generate_register_challenge(address: string, version: string): RegisterChallengeResult`

Generates a registration challenge with random salts.

#### `derive_encryption_material(...): EncryptionMaterialResult`

Derives encryption material from signature and PIN.

#### `regenerate_encryption_key(...): RegenerateKeyResult`

Regenerates an encryption key from encrypted seed.

### Key Exchange Functions

#### `get_public_key_from_encryption_key(...): { public_key: string }`

Extracts a public key from your encryption material for key exchange.

#### `create_shared_key(..., other_public_key_b64: string): SharedKeyResult`

Creates a shared encryption key between two parties using ECDH key exchange.

#### `generate_key_pair(): KeyPairResult`

Generates a standalone key pair (optional utility function).

### Key Exchange Workflow

1. **Alice** derives her encryption material and gets her public key
2. **Bob** derives his encryption material and gets his public key
3. **Alice and Bob exchange public keys**
4. **Both parties** create the same shared key using the other's public key
5. **Encrypt/decrypt messages** using the shared key

## Development

```bash
# Build WASM package
bun run build-node

# Run tests
bun run test
```
