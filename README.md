# Davinci Circom Circuits

This repository includes the templates that compose the zk-snark circuit that allows to prove a valid vote, including the format of the vote itself and its encryption:
 * **Ballot checker** ([`ballot_checker.circom`](./circuits/ballot_checker.circom)): Checks that the ballot is valid under the params provided as inputs.
    ```
    template instances: 18
    non-linear constraints: 10062
    linear constraints: 0
    public inputs: 0
    private inputs: 17
    public outputs: 8
    wires: 10005
    labels: 11530
    ```
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal and checks if they match with the provided ones.
    ```
    template instances: 28
    non-linear constraints: 3577
    linear constraints: 0
    public inputs: 8
    private inputs: 0
    public outputs: 0
    wires: 3582
    labels: 19817
    ```
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption, and calculates the nullifier with the inputs provided proving that it matches with the provided one.
    ```
    template instances: 47
    non-linear constraints: 40032
    linear constraints: 0
    public inputs: 44
    private inputs: 11
    public outputs: 0
    wires: 39978
    labels: 171486
    ```
    <small>For `n_fields = 8`.</small>
 * **Ballot proof hashed inputs (MiMC7)** ([`ballot_proof_mimc.circom`](./circuits/ballot_proof_mimc.circom)): Same as `ballot_proof.circom`, but in this case each input is private unless the hash (MiMC7) of each input is provided. This circuit also proves that the given hash is correct.
    ```
    template instances: 48
    non-linear constraints: 56776
    linear constraints: 0
    public inputs: 1
    private inputs: 55 (51 belong to witness)
    public outputs: 0
    wires: 56722
    labels: 188418
    ```
    <small>For `n_fields = 8`.</small>
 * **Ballot proof hashed inputs (Poseidon)** ([`ballot_proof_poseidon.circom`](./circuits/ballot_proof_poseidon.circom)): Same as `ballot_proof.circom`, but in this case each input is private unless the hash (Poseidon) of each input is provided. This circuit also proves that the given hash is correct.
    ```
    template instances: 272
    non-linear constraints: 42048
    linear constraints: 0
    public inputs: 1
    private inputs: 55
    public outputs: 0
    wires: 41994
    labels: 182867
    ```
    <small>For `n_fields = 8`.</small>
 * **Census proof (Lean IMT)** ([`census_proof.circom`](./circuits/census_proof.circom)): Verifies an inclusion proof of a Lean Incremental MerkleTree generated with [LeanIMT Go](https://github.com/vocdoni/lean-imt-go).
    ```
    template instances: 76
    non-linear constraints: 6642
    linear constraints: 0
    public inputs: 30
    private inputs: 0
    public outputs: 0
    wires: 6671
    labels: 21124
    ```
    <small>For `maxDepth = 27` (up to 100M of leaves).</small>

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

* **Census proof (Lean IMT)**
    ```sh 
    sh prepare-circuit.sh test/census_proof_test.circom
    ```

* **Compile and prepare all**

    ```sh
    sh prepare-circuit.sh all
    ```

## Circuit testing execution

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

* **Ballot proof hashed inputs (Poseidon)**
    ```sh 
    go test -timeout 30s -run ^TestCensusProofWithLeanIMT$ github.com/vocdoni/z-ircuits/test -v -count=1
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