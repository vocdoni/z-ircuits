# VocdoniZ Circom circuits (BLS12-377)

This repository includes the templates that compose the zk-snark circuit that allows to prove a valid vote, including the format of the vote itself and its encryption. 
The circuits are optimized for the **BLS12-377** curve and use **Poseidon377** for hashing (matching the Penumbra/Gnark implementation: Optimized tree-hashing with rate 7).

 * **Ballot checker** ([`ballot_checker.circom`](./circuits/ballot_checker.circom)): Checks that the ballot is valid under the params provided as inputs.
    ```
    template instances: 18
    non-linear constraints: 10071
    linear constraints: 123
    public inputs: 0
    private inputs: 17
    public outputs: 8
    wires: 10136
    labels: 11530
    ```
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal on the BLS12-377 Twisted Edwards curve and checks if they match with the provided ones.
    * Uses Poseidon377 (rate 1) for random nonce `k` derivation.
    ```
    template instances: 24
    non-linear constraints: 3356
    linear constraints: 3217
    public inputs: 8
    ```
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption, calculates the vote ID, and verifies the hash of all public/private inputs using Poseidon377 MultiHash.
    ```
    template instances: 214
    non-linear constraints: 42601
    linear constraints: 30033
    public inputs: 1
    private inputs: 55
    public outputs: 0
    wires: 72587
    labels: 137388
    ```
    <small>For `n_fields = 8`.</small>

## Circuit compilation for testing 

#### Requirements:
 * [Go](https://go.dev/)
 * [Rust](https://www.rust-lang.org/)
 * [Node & NPM](https://nodejs.org/)
 * [Snarkjs](https://github.com/vocdoni/snarkjs) (Custom fork with BLS12-377 support)
 * [Circom](https://docs.circom.io/)

To test the circuits, first they should be compiled to generate the wasm, the proving and the verification key. The circuits can be compiled using `prepare-circuit.sh` script and the testing circuits under `test/` folder. The script automatically handles dependencies (cloning custom snarkjs fork, etc).

* **Ballot checker**
    ```sh 
    ./prepare-circuit.sh test/ballot_checker_test.circom
    ```

* **Ballot cipher**
    ```sh 
    ./prepare-circuit.sh test/ballot_cipher_test.circom
    ```

* **Ballot proof**
    ```sh 
    ./prepare-circuit.sh test/ballot_proof_test.circom
    ```

* **Compile and prepare all**

    ```sh
    ./prepare-circuit.sh all
    ```

## Circuit testing execution

The circuits execution (proof generation and verification) is done using `golang`. The tests use the `poseidon377` package for reference hashing to ensure compatibility with Penumbra-style parameters.

### Go

* **Ballot checker**
    ```sh 
    go test -timeout 60s -run ^TestBallotChecker$ github.com/vocdoni/davinci-circom-circuits/test -v -count=1
    ```

* **Ballot cipher**
    ```sh 
    go test -timeout 60s -run ^TestBallotCipher$ github.com/vocdoni/davinci-circom-circuits/test -v -count=1
    ```

* **Ballot proof**
    ```sh 
    go test -timeout 60s -run ^TestBallotProof$ github.com/vocdoni/davinci-circom-circuits/test -v -count=1
    ```
