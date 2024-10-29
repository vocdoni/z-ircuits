// import { Base8, mulPointEscalar, Point, addPoint } from "@zk-kit/baby-jubjub"

import * as pkg from "@iden3/js-crypto";
const { babyJub } = pkg;

export function Encrypt(message : bigint, pubKey : [bigint,bigint], k : bigint) : [[bigint,bigint], [bigint,bigint]] {
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