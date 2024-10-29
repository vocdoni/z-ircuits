import fs from 'fs';
import * as snarkjs from 'snarkjs';
import * as pkg from "@iden3/js-crypto";
const { babyJub } = pkg;


export async function prove(inputs: any, circuit_wasm: string, proving_key: string) : Promise<[any, any]> {
    const {proof, publicSignals} = await snarkjs.groth16.fullProve(inputs, circuit_wasm, proving_key);
    return [proof, publicSignals];
}

export async function verify(vk: string, proof: any, pubSignals: any) : Promise<boolean> {
    const vkObj = JSON.parse(fs.readFileSync(vk, 'utf8'));
    return await snarkjs.groth16.verify(vkObj, pubSignals, proof);
}

export function encrypt(message : bigint, pubKey : [bigint,bigint], k : bigint) : [[bigint,bigint], [bigint,bigint]] {
    // c1 = k * G
    const c1 = babyJub.mulPointEscalar(babyJub.Base8, k);
    // s = k * pubKey
    const s = babyJub.mulPointEscalar(pubKey, k);
    // m = message * G
    const m = babyJub.mulPointEscalar(babyJub.Base8, message);
    // c2 = m + s
    const c2 = babyJub.addPoint(m, s);
    return [c1, c2];
}