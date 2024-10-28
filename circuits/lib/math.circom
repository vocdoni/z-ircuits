pragma circom 2.1.0;

template Pow(n) {
    signal input base;
    signal input exp_bits[n];
    signal output out;
    // Initialize intermediate results
    signal intermediates[n+1];
    intermediates[0] <== 1; // Start with 1

    signal squares[n];
    signal multipliers[n];
    for (var i = 0; i < n; i++) {
        var bit_index = n - 1 - i; // Start from MSB
        squares[i] <== intermediates[i] * intermediates[i];
        multipliers[i] <== 1 + exp_bits[bit_index] * (base - 1);
        intermediates[i+1] <== squares[i] * multipliers[i];
    }
    out <== intermediates[n];
}

template Sum(n) {
    signal input inputs[n];
    signal input mask[n]; // if mask[i] is 1, include in sum, otherwise ignore
    signal output out;

    signal intermediates[n+1];
    intermediates[0] <== 0;
    for (var i = 0; i < n; i++) {
        intermediates[i+1] <== intermediates[i] + (inputs[i] * mask[i]);
    }
    out <== intermediates[n];
}

template SumPow(n, e_bits) {
    signal input inputs[n];
    signal input mask[n]; // if mask[i] is 1, include in sum, otherwise ignore
    signal input exp;
    signal output out;

    component n2b = Num2Bits(e_bits);
    n2b.in <== exp;

    signal powers[n];
    component pow[n];
    for (var i = 0; i < n; i++) {
        pow[i] = Pow(e_bits);
        pow[i].base <== inputs[i];
        pow[i].exp_bits <== n2b.out;
        powers[i] <== pow[i].out;
    }

    component sum = Sum(n);
    sum.inputs <== powers;
    sum.mask <== mask;
    out <== sum.out;
}