import sodium from "libsodium-wrappers-sumo";
import { p256 } from "@noble/curves/nist.js";

function strip0x(s: string): string {
    return s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
}

function hexDecodeChecked(
    s: string
): { ok: true; v: Uint8Array } | { ok: false; error: string } {
    const s2 = strip0x(s);
    if (s2.length % 2 !== 0) return { ok: false as const, error: "hex string must have even length" };
    if (!/^[0-9a-fA-F]*$/.test(s2)) return { ok: false as const, error: "invalid hex characters" };
    try {
        const u = new Uint8Array(s2.length / 2);
        for (let i = 0; i < u.length; i++) {
            u[i] = parseInt(s2.substr(i * 2, 2), 16);
        }
        return { ok: true as const, v: u };
    } catch (e) {
        return { ok: false as const, error: "hex decode failed" };
    }
}

function bytesTo0xHex(bytes: Uint8Array): string {
    return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function okVal<T>(value: T) {
    return { ok: true as const, value };
}
function errMsg(msg: string) {
    return { ok: false as const, error: msg };
}

async function generateRandomBytes(len: number): Promise<Uint8Array> {
    const buf = new Uint8Array(len);
    crypto.getRandomValues(buf);
    return buf;
}

let sodiumReady = false;
async function ensureSodium() {
    if (!sodiumReady) {
        await sodium.ready;
        sodiumReady = true;
    }
}

type Argon2idHash = (password: Uint8Array, salt: Uint8Array) => Promise<Uint8Array>;
type WasmZeroize = (u: Uint8Array | null | undefined) => Promise<void>;

export function genMod(options: {
    argon2idHash: Argon2idHash,
    wasmZeroize: WasmZeroize
}) {
    const { argon2idHash, wasmZeroize } = options;

    async function hkdfExtractExpand(
        salt: Uint8Array | null,
        ikm: Uint8Array,
        info: Uint8Array,
        length: number
    ): Promise<Uint8Array> {
        const subtle = crypto.subtle;
        const hkdfKey = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
        const derivedBits = await subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: (salt ?? new Uint8Array([])) as BufferSource, info: (info ?? new Uint8Array([])) as BufferSource },
            hkdfKey,
            length * 8
        );
        return new Uint8Array(derivedBits);
    }


    async function generateRandomHex() {
        try {
            const buf = await generateRandomBytes(32);
            const hex = bytesTo0xHex(buf);
            await wasmZeroize(buf);
            return okVal(hex);
        } catch (e) {
            return errMsg("rng failure");
        }
    }

    type DerivationResult = {
        commitment: string;
        enc_seed: string;
        encryption_key: string;
    };

    async function deriveEncryptionMaterial(
        signatureHex: string,
        pin: string,
        pinSaltHex: string,
        authSaltHex: string,
        wrapperSaltHex: string,
        infoHex: string
    ): Promise<{ ok: true; value: DerivationResult } | { ok: false; error: string }> {
        const ps = hexDecodeChecked(pinSaltHex); if (!ps.ok) return errMsg(`pin_salt_hex: ${ps.error}`);
        const asalt = hexDecodeChecked(authSaltHex); if (!asalt.ok) return errMsg(`auth_salt_hex: ${asalt.error}`);
        const ws = hexDecodeChecked(wrapperSaltHex); if (!ws.ok) return errMsg(`wrapper_salt_hex: ${ws.error}`);
        const sig = hexDecodeChecked(signatureHex); if (!sig.ok) return errMsg(`signature_hex: ${sig.error}`);

        let pinKey: Uint8Array | undefined = undefined;
        try {
            pinKey = await argon2idHash(new TextEncoder().encode(pin), ps.v);
        } catch (e) {
            return errMsg("argon2 failed");
        }

        let authKey: Uint8Array | undefined = undefined;
        try {
            authKey = await hkdfExtractExpand(asalt.v, sig.v, new TextEncoder().encode("auth key"), 32);
        } catch (e) {
            await wasmZeroize(pinKey!);
            return errMsg("hkdf(auth) failed");
        }

        const x = new Uint8Array(32);
        for (let i = 0; i < 32; i++) x[i] = (authKey as any)[i] ^ (pinKey as any)[i];

        let wrapperKey: Uint8Array | null = null;
        try {
            wrapperKey = await hkdfExtractExpand(ws.v, x, new TextEncoder().encode("wrapper key"), 32);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x);
            return errMsg("hkdf(wrapper) failed");
        }

        let seed: Uint8Array | null = null;
        try {
            seed = await generateRandomBytes(32);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey);
            return errMsg("rng failure");
        }


        const commitBuf = new Uint8Array(await crypto.subtle.digest("SHA-256", seed as BufferSource));

        try {
            await ensureSodium();
        } catch (_) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed);
            return errMsg("sodium init failed");
        }

        const nonce24 = await generateRandomBytes(24);
        const aeadKey = wrapperKey!;
        let ciphertext: Uint8Array;
        try {
            ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                seed,
                null,
                null,
                nonce24,
                aeadKey
            );
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed); await wasmZeroize(nonce24);
            return errMsg("encryption failed");
        }

        const infoBytesDecoded = hexDecodeChecked(infoHex);
        if (!infoBytesDecoded.ok) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed); await wasmZeroize(nonce24); await wasmZeroize(ciphertext);
            return errMsg(`info_hex: ${infoBytesDecoded.error}`);
        }

        let encryptionKey: Uint8Array | null = null;
        try {
            encryptionKey = await hkdfExtractExpand(null, seed, infoBytesDecoded.v, 32);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed); await wasmZeroize(nonce24); await wasmZeroize(ciphertext);
            return errMsg("hkdf(seed) failed");
        }


        await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed);

        const encCombined = new Uint8Array(nonce24.length + ciphertext.length);
        encCombined.set(nonce24, 0);
        encCombined.set(ciphertext, nonce24.length);

        const res: DerivationResult = {
            commitment: bytesTo0xHex(commitBuf),
            enc_seed: bytesTo0xHex(encCombined),
            encryption_key: bytesTo0xHex(encryptionKey!),
        };


        await wasmZeroize(nonce24); await wasmZeroize(ciphertext); await wasmZeroize(encryptionKey); await wasmZeroize(encCombined); await wasmZeroize(infoBytesDecoded.v);

        return okVal(res);
    }

    type RegenerationResult = { encryption_key: string };

    async function regenerateEncryptionKey(
        signatureHex: string,
        pin: string,
        pinSaltHex: string,
        authSaltHex: string,
        wrapperSaltHex: string,
        encSeedHex: string,
        infoHex: string
    ): Promise<{ ok: true; value: RegenerationResult } | { ok: false; error: string }> {
        const ps = hexDecodeChecked(pinSaltHex); if (!ps.ok) return errMsg(`pin_salt_hex: ${ps.error}`);
        const asalt = hexDecodeChecked(authSaltHex); if (!asalt.ok) return errMsg(`auth_salt_hex: ${asalt.error}`);
        const ws = hexDecodeChecked(wrapperSaltHex); if (!ws.ok) return errMsg(`wrapper_salt_hex: ${ws.error}`);
        const sig = hexDecodeChecked(signatureHex); if (!sig.ok) return errMsg(`signature_hex: ${sig.error}`);
        const encCombinedDecoded = hexDecodeChecked(encSeedHex); if (!encCombinedDecoded.ok) return errMsg(`enc_seed_hex: ${encCombinedDecoded.error}`);

        if (encCombinedDecoded.v.length < 24) return errMsg("enc_seed too short");
        const nonce24 = encCombinedDecoded.v.slice(0, 24);
        const ciphertext = encCombinedDecoded.v.slice(24);

        let pinKey: Uint8Array;
        try {
            pinKey = await argon2idHash(new TextEncoder().encode(pin), ps.v);
        } catch (e) {
            return errMsg("argon2 failed");
        }

        let authKey: Uint8Array;
        try {
            authKey = await hkdfExtractExpand(asalt.v, sig.v, new TextEncoder().encode("auth key"), 32);
        } catch (e) {
            await wasmZeroize(pinKey);
            return errMsg("hkdf(auth) failed");
        }

        const x = new Uint8Array(32);
        for (let i = 0; i < 32; i++) x[i] = (authKey as any)[i] ^ (pinKey as any)[i];

        let wrapperKey: Uint8Array | null = null;
        try {
            wrapperKey = await hkdfExtractExpand(ws.v, x, new TextEncoder().encode("wrapper key"), 32);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x);
            return errMsg("hkdf(wrapper) failed");
        }

        try {
            await ensureSodium();
        } catch (_) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey);
            return errMsg("sodium init failed");
        }

        let seed: Uint8Array | null = null;
        try {
            seed = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce24, wrapperKey);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey);
            return errMsg("decrypt failed - wrong pin or corrupted data");
        }

        const infoDecoded = hexDecodeChecked(infoHex); if (!infoDecoded.ok) { await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed); return errMsg(`info_hex: ${infoDecoded.error}`); }

        let encryptionKey: Uint8Array | null = null;
        try {
            encryptionKey = await hkdfExtractExpand(null, seed!, infoDecoded.v, 32);
        } catch (e) {
            await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed);
            return errMsg("hkdf(seed) failed");
        }

        await wasmZeroize(authKey); await wasmZeroize(pinKey); await wasmZeroize(x); await wasmZeroize(wrapperKey); await wasmZeroize(seed);

        const res: RegenerationResult = { encryption_key: bytesTo0xHex(encryptionKey!) };

        await wasmZeroize(encryptionKey);
        await wasmZeroize(infoDecoded.v);
        await wasmZeroize(nonce24);
        await wasmZeroize(ciphertext);
        await wasmZeroize(encCombinedDecoded.v);

        return okVal(res);
    }

    type KeyPairResult = { private_key: string; public_key: string };

    async function generateKeyPair(): Promise<{ ok: true; value: KeyPairResult } | { ok: false; error: string }> {
        try {
            const privateKey = p256.utils.randomSecretKey();
            const publicKeyCompressed = p256.getPublicKey(privateKey, true);

            const res: KeyPairResult = {
                private_key: bytesTo0xHex(privateKey),
                public_key: bytesTo0xHex(publicKeyCompressed),
            };

            await wasmZeroize(privateKey);
            await wasmZeroize(publicKeyCompressed);

            return okVal(res);
        } catch (e) {
            return errMsg("keypair generation failed");
        }
    }

    type SharedKeyResult = { shared_key: string };

    async function createSharedKey(selfPrivateKeyHex: string, otherPublicKeyHex: string): Promise<{ ok: true; value: SharedKeyResult } | { ok: false; error: string }> {
        const pkDecoded = hexDecodeChecked(selfPrivateKeyHex); if (!pkDecoded.ok) return errMsg(`self_private_key_hex: ${pkDecoded.error}`);
        if (pkDecoded.v.length !== 32) return errMsg("private key must be 32 bytes");
        const priv = pkDecoded.v;

        const otherDecoded = hexDecodeChecked(otherPublicKeyHex); if (!otherDecoded.ok) { await wasmZeroize(priv); return errMsg(`other_public_key_hex: ${otherDecoded.error}`); }
        let otherPubFull: Uint8Array;
        try {
            if (otherDecoded.v.length === 32) {
                otherPubFull = new Uint8Array(33);
                otherPubFull[0] = 0x02;
                otherPubFull.set(otherDecoded.v, 1);
            } else if (otherDecoded.v.length === 33 || otherDecoded.v.length === 65) {
                otherPubFull = otherDecoded.v;
            } else {
                await wasmZeroize(priv);
                return errMsg("invalid other public key (length)");
            }

            let otherPubUncompressed: Uint8Array;
            if (otherPubFull.length === 33) {
                otherPubUncompressed = p256.Point.fromHex(bytesTo0xHex(otherPubFull).slice(2)).toBytes(false);
            } else if (otherPubFull.length === 65) {
                otherPubUncompressed = otherPubFull;
            } else {
                await wasmZeroize(priv);
                await wasmZeroize(otherPubFull);
                return errMsg("invalid other public key format");
            }

            const shared = p256.getSharedSecret(priv, otherPubUncompressed);
            const sharedSecret = shared instanceof Uint8Array ? shared : new Uint8Array(shared);
            const sharedKey = await hkdfExtractExpand(null, sharedSecret, new TextEncoder().encode("shared encryption key"), 32);

            const res: SharedKeyResult = { shared_key: bytesTo0xHex(sharedKey) };

            await wasmZeroize(priv);
            await wasmZeroize(otherDecoded.v);
            await wasmZeroize(otherPubFull);
            await wasmZeroize(otherPubUncompressed);
            await wasmZeroize(sharedSecret);
            await wasmZeroize(sharedKey);

            return okVal(res);
        } catch (e) {
            await wasmZeroize(pkDecoded.v);
            await wasmZeroize(otherDecoded.v);
            return errMsg("shared key creation failed");
        }
    }

    type PublicKeyResult = { public_key: string };

    async function getPublicKeyFromRegenerated(
        signatureHex: string,
        pin: string,
        pinSaltHex: string,
        authSaltHex: string,
        wrapperSaltHex: string,
        encSeedHex: string,
        cidHex: string
    ): Promise<{ ok: true; value: PublicKeyResult } | { ok: false; error: string }> {
        const regen = await regenerateEncryptionKey(signatureHex, pin, pinSaltHex, authSaltHex, wrapperSaltHex, encSeedHex, cidHex);
        if (!regen.ok) {
            return errMsg(regen.error);
        }

        const encryptionKeyHex = regen.value.encryption_key;
        const ekDecoded = hexDecodeChecked(encryptionKeyHex); if (!ekDecoded.ok) return errMsg(`encryption_key hex: ${ekDecoded.error}`);
        if (ekDecoded.v.length !== 32) { await wasmZeroize(ekDecoded.v); return errMsg("encryption key must be 32 bytes"); }

        try {
            const priv = ekDecoded.v;
            const pubUncompressed = p256.getPublicKey(priv, false);
            const publicX = pubUncompressed.slice(1, 33);

            const res: PublicKeyResult = { public_key: bytesTo0xHex(publicX) };

            await wasmZeroize(priv);
            await wasmZeroize(pubUncompressed);
            await wasmZeroize(publicX);

            return okVal(res);
        } catch (e) {
            await wasmZeroize(ekDecoded.v);
            return errMsg("invalid encryption key as private scalar");
        }
    }

    return { generateRandomHex, deriveEncryptionMaterial, regenerateEncryptionKey, generateKeyPair, createSharedKey, getPublicKeyFromRegenerated };
}
