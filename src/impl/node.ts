import argon2 from "argon2";
import { SecretBuffer } from "../../pkg-node/zeroize_wasm";

import { ARGON_MEMORY_COST_KIB, ARGON_PARALLELISM_DEGREE, ARGON_TIMES_COST } from "../constants";
import { genMod } from "../lib";

let wasmReady = false;
async function ensureWasm() {
    if (!wasmReady) {
        wasmReady = true;
    }
}

async function wasmZeroize(u: Uint8Array | null | undefined) {
    if (!u) return;
    try {

        await ensureWasm();
        try {
            const sb = new SecretBuffer(u.length);

            sb.write(u);

            u.fill(0);

            sb.zeroize();

            sb.free();
            return;
        } catch (e) {

        }
    } catch (e) {

    }

    try {
        u.fill(0);
    } catch (e) {

    }
}

async function argon2idHash(password: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    const result = await argon2.hash(
        Buffer.from(password),
        {
            salt: Buffer.from(salt),
            timeCost: ARGON_TIMES_COST,
            memoryCost: ARGON_MEMORY_COST_KIB,
            parallelism: ARGON_PARALLELISM_DEGREE,
            hashLength: 32,
            type: argon2.argon2id,
            raw: true,
        });
    return new Uint8Array(result);
}

const mod = genMod({ argon2idHash, wasmZeroize });
export default mod;
