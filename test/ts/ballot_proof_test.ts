import { encrypt, hexToField, prove, verify, voteId } from './utils';

(async () => {
    const wasm = "../../artifacts/ballot_proof_test.wasm";
    const pk = "../../artifacts/ballot_proof_test_pkey.zkey";
    const vk = "../../artifacts/ballot_proof_test_vkey.json";
    // encrypt fields
    const pubKey: [bigint, bigint] = [
        BigInt("14683031697277856265190472023105198820413415816394525437006041413571428119286"),
        BigInt("8231930431069649913978957226360235712312621187451969137400305691913512440493")
    ];
    const k: bigint = BigInt("650538809577380042220943083323036196153738464670981167525900386056100355632");
    const n_fields = 8;
    const fields = [1, 2, 3, 4, 5];
    // fill with zeros to reach n_fields both fields and cipherfields
    const cipherfields: BigInt[][][] = new Array(n_fields).fill(0).map(() => [
        [BigInt(0), BigInt(0)],
        [BigInt(0), BigInt(0)],
    ]);
    for (let i = 0; i < n_fields; i++) {
        if (i < fields.length) {
            cipherfields[i] = encrypt(BigInt(fields[i]), pubKey, k)
        } else {
            fields.push(0);
        }
    }
    // compute nullifier
    const address = hexToField("0x6Db989fbe7b1308cc59A27f021e2E3de9422CF0A");
    const process_id = hexToField("0xf16236a51F11c0Bf97180eB16694e3A345E42506");
    const vote_id = await voteId(process_id, address, k);
    // init inputs
    const inputs = {
        fields,
        num_fields: 5,
        unique_values: 1,
        max_value: 5 + 1,
        min_value: 0,
        max_value_sum: 56,
        min_value_sum: 5,
        cost_exponent: 2,
        cost_from_weight: 0,
        encryption_pubkey: pubKey,
        k,
        address,
        process_id,
        vote_id,
        weight: 0,
        cipherfields,
    };
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