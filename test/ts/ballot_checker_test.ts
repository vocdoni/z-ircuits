import { prove, verify } from './utils';

(async () => {
    const wasm = "../../artifacts/ballot_checker_test.wasm";
    const pk = "../../artifacts/ballot_checker_test_pkey.zkey";
    const vk = "../../artifacts/ballot_checker_test_vkey.json";
    // init inputs
    const inputs = {
        fields: [1, 2, 3, 4, 5, 0, 0, 0],
        num_fields: 5,
        unique_values: 1,
        max_value: 5,
        min_value: 0,
        max_value_sum: 56,
        min_value_sum: 5,
        cost_exponent: 2,
        weight: 0,
        cost_from_weight: 0,
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
