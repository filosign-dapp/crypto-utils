import argon2 from "argon2-browser";
import init, { SecretBuffer } from "../../pkg/zeroize_wasm";

import { ARGON_MEMORY_COST_KIB, ARGON_PARALLELISM_DEGREE, ARGON_TIMES_COST } from "../constants";
import { genMod } from "../lib";

let wasmReady = false;
async function ensureWasm() {
    if (!wasmReady) {
        await init();
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
    const result = await argon2.hash({
        pass: password,
        salt,
        time: ARGON_TIMES_COST,
        mem: ARGON_MEMORY_COST_KIB,
        parallelism: ARGON_PARALLELISM_DEGREE,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id,
    });
    return new Uint8Array(result.hash);
}

const mod = genMod({ argon2idHash, wasmZeroize });
export default mod;
