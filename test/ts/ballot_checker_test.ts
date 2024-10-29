import { prove, verify } from './utils';

(async () => {
    const wasm = "../../artifacts/ballot_checker_test.wasm";
    const pk = "../../artifacts/ballot_checker_test_pkey.zkey";
    const vk = "../../artifacts/ballot_checker_test_vkey.json";
    
    const inputs = {
        fields: [ 1, 2, 3, 4, 5 ],
        max_count: 5,
        force_uniqueness: 1,
        max_value: 5 + 1,
        min_value: 0,
        max_total_cost: 56,
        min_total_cost: 5,
        cost_exp: 2,
        weight: 0,
        cost_from_weight: 0,
    };

    console.log("inputs", inputs);
    
    const [proof, publicSignals] = await prove(inputs, wasm, pk);
    
    console.log("proof", proof);
    console.log("pubSignals", publicSignals);

    const verified = await verify(vk, proof, publicSignals);
    console.log("Proof verified?", verified);

    process.exit();
})();
