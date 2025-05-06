pragma circom 2.1.0;

include "bitify.circom";
include "babyjub.circom";
include "comparators.circom";
include "escalarmulany.circom";
include "escalarmulfix.circom";

template ElGamal() {
    signal input pk[2]; // [pub] public key
    signal input msg;   // [priv] message to encrypt
    signal input k;     // [priv] random number

    signal output c1[2]; // first point of the ciphertext
    signal output c2[2]; // second point of the ciphertext

    // ensure that public key is on the curve
    component pkCheck = BabyCheck();
    pkCheck.x <== pk[0];
    pkCheck.y <== pk[1];
    // ensure that the public key is not the identity point (0, 1)
    component isz = IsZero();
    isz.in <== pk[0];
    component ise = IsEqual();
    ise.in[0] <== pk[1];
    ise.in[1] <== 1;
    isz.out + ise.out === 0;
    // babyjubjub base point
    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    // encode the message as a point on the curve
    var msg_bits = 32;
    component messageBits = Num2Bits(msg_bits);
    messageBits.in <== msg;
    component messagePoint = EscalarMulFix(msg_bits, base);
    for (var i=0; i<msg_bits; i++) {
        messageBits.out[i] ==> messagePoint.e[i];
    }
    var k_bits = 254;
    // c1 = k * base (escalarMulFix)
    component c1Point = EscalarMulFix(k_bits, base);
    component kBits = Num2Bits(k_bits);
    kBits.in <== k;
    for (var i=0; i<k_bits; i++) {
        kBits.out[i] ==> c1Point.e[i];
    }
    // s = k * pk (escalarMulAny)
    component sPoint = EscalarMulAny(k_bits);
    sPoint.p[0] <== pk[0];
    sPoint.p[1] <== pk[1];
    for (var i=0; i<k_bits; i++) {
        kBits.out[i] ==> sPoint.e[i];
    }
    // c2 = msg + s (babyAdd)
    component c2Point = BabyAdd();
    c2Point.x1 <== messagePoint.out[0];
    c2Point.y1 <== messagePoint.out[1];
    c2Point.x2 <== sPoint.out[0];
    c2Point.y2 <== sPoint.out[1];
    // return the results
    c1[0] <== c1Point.out[0];
    c1[1] <== c1Point.out[1];
    c2[0] <== c2Point.xout;
    c2[1] <== c2Point.yout;
}