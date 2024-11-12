# VocdoniZ Circom circuits

This repository includes the templates that compose the zk-snark circuit that allows to prove a valid vote, including the format of the vote itself and its encryption:
 * **Ballot checker** ([`ballot_checker.circom`](./circuits/ballot_checker.circom)): Checks that the ballot is valid under the params provided as inputs.
    ```
    template instances: 17
    non-linear constraints: 6409
    linear constraints: 0
    public inputs: 0
    private inputs: 14
    public outputs: 5
    wires: 6384
    labels: 7298
    ```
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal and checks if they match with the provided ones.
    ```
    template instances: 26
    non-linear constraints: 3202
    linear constraints: 0
    public inputs: 8
    private inputs: 0
    public outputs: 0
    wires: 3207
    labels: 19411
    ```
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption, and calculates the nullifier with the inputs provided proving that it matches with the provided one.
    ```
    template instances: 111
    non-linear constraints: 35795
    linear constraints: 0
    public inputs: 42
    private inputs: 13
    public outputs: 0
    wires: 35744
    labels: 167345
    ```
    <small>For `n_fields = 8`.</small>
 * **Ballot proof hashed inputs (MiMC7)** ([`ballot_proof_mimc.circom`](./circuits/ballot_proof_mimc.circom)): Same as `ballot_proof.circom`, but in this case each input is private unless the hash (MiMC7) of each input is provided. This circuit also proves that the given hash is correct.
    ```
    template instances: 113
    non-linear constraints: 52175
    linear constraints: 0
    public inputs: 1
    private inputs: 55
    public outputs: 0
    wires: 55764
    labels: 187589
    ```
    <small>For `n_fields = 8`.</small>
 * **Ballot proof hashed inputs (Poseidon)** ([`ballot_proof_poseidon.circom`](./circuits/ballot_proof_poseidon.circom)): Same as `ballot_proof.circom`, but in this case each input is private unless the hash (Poseidon) of each input is provided. This circuit also proves that the given hash is correct.
    ```
    template instances: 343
    non-linear constraints: 37817
    linear constraints: 0
    public inputs: 1
    private inputs: 55
    public outputs: 0
    wires: 38249
    labels: 181444
    ```
    <small>For `n_fields = 8`.</small>

## Circuit compilation for testing 

#### Requirements:
 * [Go](https://go.dev/)
 * [Rust](https://www.rust-lang.org/)
 * [Node & NPM](https://nodejs.org/)
 * [Snarkjs](https://github.com/iden3/snarkjs)
 * [Circom](https://docs.circom.io/)

To test the circuits, first they should be compiled to generate the wasm, the proving and the verification key. The circuits can be compiled using `prepare-circuit.sh` script and the testing circuits under `test/` folder:

* **Ballot checker**
    ```sh 
    sh prepare-circuit.sh test/ballot_checker_test.circom
    ```

* **Ballot cipher**
    ```sh 
    sh prepare-circuit.sh test/ballot_cipher_test.circom
    ```

* **Ballot proof**
    ```sh 
    sh prepare-circuit.sh test/ballot_proof_test.circom
    ```

* **Ballot proof hashed inputs (MiMC7)**
    ```sh 
    sh prepare-circuit.sh test/ballot_proof_mimc_test.circom
    ```

* **Ballot proof hashed inputs (Poseidon)**
    ```sh 
    sh prepare-circuit.sh test/ballot_proof_poseidon_test.circom
    ```

## Circuit testubg execution

The circuits execution (proof generation and verification) can be done using `golang` or `typescript`:

### Go

* **Ballot checker**
    ```sh 
    go test -timeout 30s -run ^TestBallotChecker$ github.com/vocdoni/z-ircuits/test -v -count=1
    ```

* **Ballot cipher**
    ```sh 
    go test -timeout 30s -run ^TestBallotCipher$ github.com/vocdoni/z-ircuits/test -v -count=1
    ```

* **Ballot proof**
    ```sh 
    go test -timeout 30s -run ^TestBallotProof$ github.com/vocdoni/z-ircuits/test -v -count=1
    ```

* **Ballot proof hashed inputs (MiMC7)**
    ```sh 
    go test -timeout 30s -run ^TestBallotProofMiMC$ github.com/vocdoni/z-ircuits/test -v -count=1
    ```

* **Ballot proof hashed inputs (Poseidon)**
    ```sh 
    go test -timeout 30s -run ^TestBallotProofPoseidon$ github.com/vocdoni/z-ircuits/test -v -count=1
    ```

### Typescript

#### Setup
```sh
cd test/ts
npm i
npm run build
```

* **Ballot checker**
    ```sh 
    npm run ballot_checker
    ```

* **Ballot cipher**
    ```sh 
    npm run ballot_cipher
    ```

* **Ballot proof**
    ```sh 
    npm run ballot_proof
    ```

* **Ballot proof hashed inputs (Poseidon)**
    ```sh 
    npm run ballot_proof_poseidon
    ```