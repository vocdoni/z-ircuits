import { encrypt, prove, verify } from './utils';

(async () => {
    const wasm = "../../artifacts/ballot_cipher_test.wasm";
    const pk = "../../artifacts/ballot_cipher_test_pkey.zkey";
    const vk = "../../artifacts/ballot_cipher_test_vkey.json";
    // encrypt value
    const pubKey : [bigint, bigint] = [
        BigInt("14683031697277856265190472023105198820413415816394525437006041413571428119286"), 
        BigInt("8231930431069649913978957226360235712312621187451969137400305691913512440493")
    ];
    const k : bigint = BigInt("650538809577380042220943083323036196153738464670981167525900386056100355632");
    const msg : bigint = BigInt("3");
    const [c1, c2] = encrypt(msg, pubKey, k);
    // init inputs
    const inputs = { encryption_pubkey: pubKey, msg, k, c1, c2 };
    console.log("inputs", inputs);
    // generate proof
    const [proof, publicSignals] = await prove(inputs, wasm, pk);
    console.log("proof", proof);
    console.log("pubSignals", publicSignals);
    // verify proof
    const verified = await verify(vk, proof, publicSignals);
    console.log("Proof verified?", verified);
    // exit
    process.exit();
})();