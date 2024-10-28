# VocdoniZ Circom circuits

This repository includes the templates that compose the zk-snark circuit that allows to prove a valid vote, including the format of the vote itself and its encryption:
 * **Ballot checker** ([`ballot_checker.circom`](./circuits/ballot_checker.circom)): Checks that the ballot is valid under the params provided as inputs.
 * **Ballot cipher** ([`ballot_cipher.circom`](./circuits/ballot_cipher.circom)): Encrypts the ballot fields using ElGamal and checks if they match with the provided ones.
 * **Ballot proof** ([`ballot_proof.circom`](./circuits/ballot_proof.circom)): Checks the ballot and its encryption, and calculates the nullifier with the inputs provided proving that it matches with the provided one.