pragma circom 2.1.0;

include "bitify.circom";
include "comparators.circom";
include "./lib/math.circom";
include "./lib/utils.circom";

template BallotChecker(n_fields) {
    signal input fields[n_fields];
    signal input max_count;
    signal input force_uniqueness;
    signal input max_value;
    signal input min_value;
    signal input max_total_cost;
    signal input min_total_cost;
    signal input cost_exp;
    signal input cost_from_weight;
    signal input weight;
    // return the mask of valid fields to be used in other components
    signal output mask[n_fields];
    component mask_gen = MaskGenerator(n_fields);
    mask_gen.in <== max_count;
    mask <== mask_gen.out;
    // all fields must be different
    component unique = UniqueArray(n_fields);
    unique.arr <== fields;
    unique.mask <== mask;
    unique.sel <== force_uniqueness;
    // every field must be between min_value and max_value
    component inBounds = ArrayInBounds(n_fields);
    inBounds.arr <== fields;
    inBounds.mask <== mask;
    inBounds.min <== min_value;
    inBounds.max <== max_value;
    // compute total cost: sum of all fields to the power of cost_exp
    signal total_cost;
    component sum_calc = SumPow(n_fields, 128);
    sum_calc.inputs <== fields;
    sum_calc.mask <== mask;
    sum_calc.exp <== cost_exp;
    total_cost <== sum_calc.out;
    // if max_total_cost is 0, then the cost is not bounded
    component hasMax = GreaterThan(128);
    hasMax.in[0] <== max_total_cost;
    hasMax.in[1] <== 0;
    signal useMax;
    useMax <== hasMax.out;
    // select max_total_cost if cost_from_weight is 0, otherwise use weight
    component mux = Mux();
    mux.a <== max_total_cost;
    mux.b <== weight;
    mux.sel <== cost_from_weight;
    // check bounds of total_cost with min_total_cost and mux output
    component lt = LessEqThan(128);
    lt.in[0] <== total_cost;
    lt.in[1] <== mux.out;
    // lt.out === 1;
    // only enforce when max_total_cost > 0
    useMax * lt.out === useMax;
    // encrease by 1 the total_cost to allow equality with min_total_cost and 
    // avoid negative overflow decreasing min_total_cost
    component gt = GreaterThan(128);
    gt.in[0] <== total_cost + 1;
    gt.in[1] <== min_total_cost; 
    gt.out === 1;
}

