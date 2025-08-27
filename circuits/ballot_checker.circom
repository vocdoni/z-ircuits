pragma circom 2.1.0;

include "bitify.circom";
include "comparators.circom";
include "./lib/math.circom";
include "./lib/utils.circom";

template BallotChecker(n_fields) {
    signal input fields[n_fields];
    signal input num_fields;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;
    signal input weight;
    // return the mask of valid fields to be used in other components
    signal output mask[n_fields];
    component mask_gen = MaskGenerator(n_fields);
    mask_gen.in <== num_fields;
    mask <== mask_gen.out;
    // all fields must be different
    component unique = UniqueArray(n_fields);
    unique.arr <== fields;
    unique.mask <== mask;
    unique.sel <== unique_values;
    // every field must be between min_value and max_value
    component inBounds = ArrayInBounds(n_fields);
    inBounds.arr <== fields;
    inBounds.mask <== mask;
    inBounds.min <== min_value;
    inBounds.max <== max_value;
    // compute total cost: sum of all fields to the power of cost_exponent
    signal total_cost;
    component sum_calc = SumPow(n_fields, 128);
    sum_calc.inputs <== fields;
    sum_calc.mask <== mask;
    sum_calc.exp <== cost_exponent;
    total_cost <== sum_calc.out;
    // if max_value_sum is 0, then the cost is not bounded
    component hasMax = GreaterThan(128);
    hasMax.in[0] <== max_value_sum;
    hasMax.in[1] <== 0;
    signal useMax;
    useMax <== hasMax.out;
    // select max_value_sum if cost_from_weight is 0, otherwise use weight
    component mux = Mux();
    mux.a <== max_value_sum;
    mux.b <== weight;
    mux.sel <== cost_from_weight;
    // check bounds of total_cost with min_value_sum and mux output
    component lt = LessEqThan(128);
    lt.in[0] <== total_cost;
    lt.in[1] <== mux.out;
    // lt.out === 1;
    // only enforce when max_value_sum > 0
    useMax * lt.out === useMax;
    // encrease by 1 the total_cost to allow equality with min_value_sum and 
    // avoid negative overflow decreasing min_value_sum
    component gt = GreaterThan(128);
    gt.in[0] <== total_cost + 1;
    gt.in[1] <== min_value_sum; 
    gt.out === 1;
}

