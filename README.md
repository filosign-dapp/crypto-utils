# Filosign Crypto Utils

High-performance WebAssembly cryptographic utilities powering the Filosign decentralized e-signature platform. Provides secure key derivation, encryption, and digital signature operations for blockchain-based document signing.

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

## Filosign Integration

Crypto Utils powers the cryptographic operations in Filosign's decentralized e-signature workflow:

### User Registration Flow
```typescript
import { generateSalts, generateNonce, generateRegisterChallenge, deriveEncryptionMaterial } from "filosign-crypto-utils";

// Step 1: Generate cryptographic salts
const salts = generateSalts(); // PIN, auth, and wrapper salts

// Step 2: Create registration challenge
const nonce = generateNonce();
const challenge = generateRegisterChallenge(
  userAddress,
  version.toString(),
  nonce
);

// Step 3: User signs challenge with wallet
const signature = await wallet.signMessage({ message: challenge.challenge });

// Step 4: Derive encryption material from PIN + signature
const material = deriveEncryptionMaterial(
  signature,
  userPin,
  salts.pinSalt,
  salts.authSalt,
  salts.wrapperSalt,
  "filosign-encryption"
);
```

### Authentication & Key Regeneration
```typescript
import { regenerateEncryptionKey, getPublicKeyFromRegenerated } from "filosign-crypto-utils";

// Regenerate encryption key for session (login)
const { encryptionKey } = regenerateEncryptionKey(
  signature,
  userPin,
  pinSalt,
  authSalt,
  wrapperSalt,
  encryptedSeed,
  "filosign-encryption"
);

// Extract public key for blockchain registration
const { publicKey } = getPublicKeyFromRegenerated(
  signature,
  userPin,
  pinSalt,
  authSalt,
  wrapperSalt,
  encryptedSeed,
  "filosign-encryption"
);
```

### Secure Document Exchange
```typescript
import { createSharedKey } from "filosign-crypto-utils";

// Create shared encryption key for secure communication
const { sharedKey } = createSharedKey(
  myPrivateKey,
  recipientPublicKey
);

// Use sharedKey with AES-GCM for document encryption
const encryptedDocument = await encryptDocument(document, sharedKey);
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

#### `createSharedKey(selfPrivateKeyB64: string, otherPublicKeyB64: string): SharedKeyResult`

Creates a shared encryption key between two parties using ECDH key exchange.

#### `generateKeyPair(): KeyPairResult`

Generates a standalone key pair (optional utility function).

### Utility Functions

#### `generateSalt(len: number): string`

Generates a random salt of specified length in bytes, returned as base64.

#### `toHex(b64: string): string`

Converts a base64 string to hexadecimal.

#### `toB64(hexStr: string): string`

Converts a hexadecimal string to base64. Supports both prefixed (0x) and non-prefixed hex strings.

### Key Exchange Workflow

1. **Alice** generates salts and derives her encryption material
2. **Alice** gets her public key using `getPublicKeyFromEncryptionKey`
3. **Bob** generates salts and derives his encryption material
4. **Bob** gets his public key using `getPublicKeyFromEncryptionKey`
5. **Alice and Bob exchange public keys**
6. **Both parties** create the same shared key using `createSharedKey` with the other's public key
7. **Encrypt/decrypt messages** using the shared key

## Cryptographic Security Model

### Key Derivation Hierarchy
```
User PIN → Argon2 → Authentication Key
Authentication Key ⊕ PIN Key → Wrapper Key
Wrapper Key → XChaCha20-Poly1305 Encryption of Seed
Seed → HKDF → ECDSA Private Key + Encryption Keys
```

### Security Features
- **Argon2id**: Memory-hard PIN hashing (65536 iterations, 3 lanes, 1 thread)
- **XChaCha20-Poly1305**: Authenticated encryption for seed storage
- **HKDF**: Secure key derivation for multiple purposes
- **ECDH**: Ephemeral key exchange for document encryption
- **Memory Zeroization**: Sensitive data cleared after use

### Integration Architecture

Crypto Utils integrates with Filosign's multi-layered security:

1. **Client Layer**: WebAssembly cryptographic operations
2. **Smart Contracts**: On-chain verification and storage
3. **Decentralized Storage**: IPFS/Filecoin document storage
4. **Wallet Integration**: MetaMask/WalletConnect signature verification

## Performance

- **WebAssembly**: Near-native performance for cryptographic operations
- **Zero-copy Operations**: Efficient memory management
- **Streaming Support**: Large file encryption capabilities

## Development

```bash
# Install dependencies
bun install

# Build WASM package for both web and Node.js targets
bun run build

# Run tests
bun run test

# Development workflow
bun run build && bun run test
```

## License

AGPL-3.0-or-later
