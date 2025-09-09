# FiloSign Crypto Utils

WebAssembly-based cryptographic utilities for FiloSign.

## Installation

### From GitHub (for development)

```bash
npm install git+https://github.com/filosign-dapp/crypto-utils.git
```

### From npm (when published)

```bash
npm install filosign-crypto-utils
```

## Usage

```typescript
import {
  generate_register_challenge,
  derive_encryption_material,
  regenerate_encryption_key,
  type RegisterChallengeResult,
  type EncryptionMaterialResult,
  type RegenerateKeyResult,
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
```

## API

### `generate_register_challenge(address: string, version: string): RegisterChallengeResult`

Generates a registration challenge with random salts.

### `derive_encryption_material(...): EncryptionMaterialResult`

Derives encryption material from signature and PIN.

### `regenerate_encryption_key(...): RegenerateKeyResult`

Regenerates an encryption key from encrypted seed.

## Development

```bash
# Build WASM package
npm run build-node

# Run tests
npm test
```
