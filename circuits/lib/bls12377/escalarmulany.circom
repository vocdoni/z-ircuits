pragma circom 2.0.0;

include "twisted_edwards.circom";

// Variable-base scalar multiplication using standard double-and-add on Edwards.
// Bits are little-endian: e[0] is LSB.
template EscalarMulAny(n) {
    signal input e[n];
    signal input p[2];    // Edwards affine
    signal output out[2]; // Edwards affine

    signal accX[n + 1];
    signal accY[n + 1];
    accX[n] <== 0;
    accY[n] <== 1; // identity

    if (n > 0) {
        component d[n];
        component add[n];
        for (var i = n - 1; i >= 0; i--) {
            var idx = n - 1 - i; // forward index for arrays
            d[idx] = PointDouble();
            add[idx] = PointAdd();

            d[idx].x <== accX[i+1];
            d[idx].y <== accY[i+1];

            add[idx].x1 <== d[idx].xout;
            add[idx].y1 <== d[idx].yout;
            add[idx].x2 <== p[0];
            add[idx].y2 <== p[1];

            accX[i] <== (add[idx].xout - d[idx].xout) * e[i] + d[idx].xout;
            accY[i] <== (add[idx].yout - d[idx].yout) * e[i] + d[idx].yout;
        }
    }

    out[0] <== accX[0];
    out[1] <== accY[0];
}
