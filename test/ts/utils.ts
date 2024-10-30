import fs from 'fs';
import * as snarkjs from 'snarkjs';
import * as pkg from "@iden3/js-crypto";
const { babyJub, poseidon } = pkg;

const q = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function strip0x(value: string): string {
    return value.startsWith('0x') ? value.substring(2) : value;
}

export function bigIntToField(bi: bigint): bigint {
    if (bi == q) {
        return BigInt(0);
    } else if (bi < q && bi != BigInt(0)) {
        return bi;
    }
    return bi % q;
}

export function hexToField(hexStr: string): bigint {
    hexStr = strip0x(hexStr);
    if (hexStr.length % 2) {
        hexStr = "0" + hexStr;
    }
    return bigIntToField(BigInt("0x" + hexStr));
}

export function strToBigInt(str: string): bigint {
    const hex = Array.from(str)
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
    return BigInt('0x' + hex);
}

export const hash = poseidon.hash;

export async function prove(inputs: any, circuit_wasm: string, proving_key: string): Promise<[any, any]> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, circuit_wasm, proving_key);
    return [proof, publicSignals];
}

export async function verify(vk: string, proof: any, pubSignals: any): Promise<boolean> {
    const vkObj = JSON.parse(fs.readFileSync(vk, 'utf8'));
    return await snarkjs.groth16.verify(vkObj, pubSignals, proof);
}

export function encrypt(message: bigint, pubKey: [bigint, bigint], k: bigint): [[bigint, bigint], [bigint, bigint]] {
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