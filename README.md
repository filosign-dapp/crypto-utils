# FiloSign Crypto Utils

WebAssembly-based cryptographic utilities designed specifically for FiloSign.

## Installation

### From npm

```bash
npm install filosign-crypto-utils
# or
yarn add filosign-crypto-utils
# or
bun add filosign-crypto-utils
```

### From GitHub (for development)

```bash
bun add git+https://github.com/filosign-dapp/crypto-utils.git
```

## Usage

```typescript
import {
  generateRegisterChallenge,
  deriveEncryptionMaterial,
  regenerateEncryptionKey,
  generateKeyPair,
  createSharedKey,
  getPublicKeyFromEncryptionKey,
  getPublicKeyFromRegenerated,
  generateSalts,
  generateNonce,
  generateSalt,
  toHex,
  toB64,
  type RegisterChallengeResult,
  type EncryptionMaterialResult,
  type RegenerateKeyResult,
  type KeyPairResult,
  type SharedKeyResult,
  type SaltsResult,
} from "filosign-crypto-utils";

// Generate salts for registration
const salts = generateSalts();

// Generate a nonce for challenge
const nonce = generateNonce();

// Generate a registration challenge
const challenge = generateRegisterChallenge("0x1234...", "1", nonce);

// Derive encryption material
const material = deriveEncryptionMaterial(
  signatureB64,
  pin,
  salts.pinSalt,
  salts.authSalt,
  salts.wrapperSalt,
  "info-context"
);

// Regenerate encryption key
const key = regenerateEncryptionKey(
  signatureB64,
  pin,
  salts.pinSalt,
  salts.authSalt,
  salts.wrapperSalt,
  material.encSeed,
  "info-context"
);

// Get public key from encryption material (for key exchange)
const publicKeyResult = getPublicKeyFromEncryptionKey(
  signatureB64,
  pin,
  salts.pinSalt,
  salts.authSalt,
  salts.wrapperSalt,
  material.encSeed,
  "info-context"
);

// Create shared key with another party's public key
const sharedKey = createSharedKey(
  signatureB64,
  pin,
  salts.pinSalt,
  salts.authSalt,
  salts.wrapperSalt,
  material.encSeed,
  "info-context",
  otherPartyPublicKey
);

// Generate standalone key pairs (optional)
const keyPair = generateKeyPair();
```

## API

### Core Functions

#### `generateSalts(): SaltsResult`

Generates random salts for pin, auth, and wrapper operations.

#### `generateNonce(): string`

Generates a random nonce for challenge creation.

#### `generateRegisterChallenge(address: string, version: string, nonceB64: string): RegisterChallengeResult`

Generates a registration challenge with the given address, version, and nonce.

#### `deriveEncryptionMaterial(signatureB64: string, pin: string, pinSaltB64: string, authSaltB64: string, wrapperSaltB64: string, info: string): EncryptionMaterialResult`

Derives encryption material from signature, PIN, salts, and info context.

#### `regenerateEncryptionKey(signatureB64: string, pin: string, pinSaltB64: string, authSaltB64: string, wrapperSaltB64: string, encSeedB64: string, info: string): RegenerateKeyResult`

Regenerates an encryption key from encrypted seed and parameters.

### Key Exchange Functions

#### `getPublicKeyFromEncryptionKey(signatureB64: string, pin: string, pinSaltB64: string, authSaltB64: string, wrapperSaltB64: string, encSeedB64: string, info: string): { publicKey: string }`

Extracts a public key from your encryption material for key exchange.

#### `getPublicKeyFromRegenerated(signatureB64: string, pin: string, pinSaltB64: string, authSaltB64: string, wrapperSaltB64: string, encSeedB64: string, info: string): { publicKey: string }`

Gets a public key from regenerated encryption material.

#### `createSharedKey(signatureB64: string, pin: string, pinSaltB64: string, authSaltB64: string, wrapperSaltB64: string, encSeedB64: string, info: string, otherPublicKeyB64: string): SharedKeyResult`

Creates a shared encryption key between two parties using ECDH key exchange.

#### `generateKeyPair(): KeyPairResult`

Generates a standalone key pair (optional utility function).

### Utility Functions

#### `generateSalt(len: number): string`

Generates a random salt of specified length in bytes, returned as base64.

#### `toHex(b64: string): string`

Converts a base64 string to hexadecimal.

#### `toB64(hexStr: string): string`

Converts a hexadecimal string to base64.

### Key Exchange Workflow

1. **Alice** generates salts and derives her encryption material
2. **Alice** gets her public key using `getPublicKeyFromEncryptionKey`
3. **Bob** generates salts and derives his encryption material
4. **Bob** gets his public key using `getPublicKeyFromEncryptionKey`
5. **Alice and Bob exchange public keys**
6. **Both parties** create the same shared key using `createSharedKey` with the other's public key
7. **Encrypt/decrypt messages** using the shared key

## Development

```bash
# Build WASM package
bun run build-node

# Run tests
bun run test
```
