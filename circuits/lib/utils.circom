pragma circom 2.1.0;

template Mux() {
    signal input a;
    signal input b;
    signal input sel;
    signal output out;
    // constraint to ensure 'sel' is a valid bit (0 or 1)
    sel * (sel - 1) === 0;
    // mux Logic: C = A + sel * (B - A)
    //  - if sel = 0, C = A
    //  - if sel = 1, C = B
    out <== a + sel * (b - a);
}

template UniqueArray(n) {
    signal input arr[n];
    signal input mask[n]; // if mask[i] is 1, then enforce uniqueness, otherwise do nothing
    signal input sel; // if sel is 1, then enforce uniqueness, otherwise do nothing

    component iseq[n][n];
    signal intermediate[n][n];
    signal intermediate_mask[n][n];
    for (var i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
            if (j != i) {
                iseq[i][j] = IsEqual();
                iseq[i][j].in[0] <== arr[i];
                iseq[i][j].in[1] <== arr[j];
                
                intermediate_mask[i][j] <== mask[i] * mask[j];
                intermediate[i][j] <== iseq[i][j].out * intermediate_mask[i][j];
                intermediate[i][j] * sel === 0;
            }
        }
    }
}

template ArrayInBounds(n) {
    signal input arr[n];
    signal input mask[n]; // if mask[i] is 1, then enforce bounds, otherwise do nothing
    signal input min;
    signal input max;

    component lt[n];
    component gt[n];
    for (var i = 0; i < n; i++) {
        // enforce each element is in bounds
        lt[i] = GreaterThan(252);
        lt[i].in[0] <== arr[i];
        lt[i].in[1] <== max + 1;
        lt[i].out * mask[i] === 0;

        gt[i] = LessThan(252);
        gt[i].in[0] <== arr[i];
        gt[i].in[1] <== min - 1;
        gt[i].out * mask[i] === 0;
    }
}

template MaskGenerator(n) {
    signal input in;
    signal output out[n];

    component control = LessThan(252);
    control.in[0] <== in;
    control.in[1] <== n + 1;
    assert(control.out == 1);

    component lt[n];
    for (var i = 0; i < n; i++) {
        lt[i] = LessThan(252);
        lt[i].in[0] <== i;
        lt[i].in[1] <== in;
        out[i] <== lt[i].out;
    }
}