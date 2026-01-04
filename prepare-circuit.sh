#!/bin/bash

# Create deps directory
DEPS_DIR="$PWD/deps"
if [ ! -d "$DEPS_DIR" ]; then
    mkdir "$DEPS_DIR"
fi

CIRCOM_BIN="circom"

if ! command -v $CIRCOM_BIN &> /dev/null; then
    if [ -f "$DEPS_DIR/circom" ]; then
        CIRCOM_BIN="$DEPS_DIR/circom"
    else
        echo "Circom not found, installing to $DEPS_DIR..."
        wget -q https://github.com/iden3/circom/releases/download/v2.2.3/circom-linux-amd64 -O "$DEPS_DIR/circom"
        if [ $? -ne 0 ]; then
            echo "Failed to download circom"
            exit 1
        fi
        chmod +x "$DEPS_DIR/circom"
        CIRCOM_BIN="$DEPS_DIR/circom"
    fi
fi

$CIRCOM_BIN --version > /dev/null
if [ $? -ne 0 ]; then
   echo "Circom check failed"
   exit 1
fi

# if artifacts directory is not provided, use the default one
if [ -z "$2" ]; then
    ARTIFACTS_DIR="$PWD/artifacts"
fi
if [ ! -d "$ARTIFACTS_DIR" ]; then
    mkdir "$ARTIFACTS_DIR"
fi

# check if npm is installed
if [ ! command -v npm &> /dev/null ]; then
    echo "npm is not installed"
    exit 1
fi

# Check/Install SnarkJS (Custom fork with BLS12-377)
SNARKJS_DIR="$DEPS_DIR/snarkjs"
SNARKJS="node $SNARKJS_DIR/cli.js"

if [ ! -d "$SNARKJS_DIR" ] || [ -z "$(ls -A "$SNARKJS_DIR" 2>/dev/null)" ]; then
    echo "snarkjs not found, cloning..."
    # Clean stale empty dir
    if [ -d "$SNARKJS_DIR" ] && [ -z "$(ls -A "$SNARKJS_DIR" 2>/dev/null)" ]; then
        rmdir "$SNARKJS_DIR"
    fi
    git clone https://github.com/p4u/snarkjs.git "$SNARKJS_DIR"
    cd "$SNARKJS_DIR"
    git submodule update --init --recursive
    npm install
    cd -
fi

# install circomlib
echo "=> Install circomlib"
npm install circomlib

# set circuit to the first argument or default to ballot_proof
CIRCUIT="${1:-circuits/ballot_proof.circom}"

for C in $CIRCUIT; do
  # compile the circuit
  echo "=> Compiling circuit $C"
  $CIRCOM_BIN $C --r1cs --wasm --sym --prime bls12377 -o $ARTIFACTS_DIR \
    -l ./circuits/lib/bls12377 \
    -l ./circuits \
    -l ./node_modules/circomlib/circuits \
  
  # check if ptau file exists, if not generate it for bls12377
  if [ ! -f "$ARTIFACTS_DIR/ptau" ]; then
      echo "Generating ptau file for bls12377..."
      $SNARKJS powersoftau new bls12377 18 $ARTIFACTS_DIR/ptau_0.ptau -v
      $SNARKJS powersoftau contribute $ARTIFACTS_DIR/ptau_0.ptau $ARTIFACTS_DIR/ptau_1.ptau --name="First contribution" -v -e="some random text"
      $SNARKJS powersoftau prepare phase2 $ARTIFACTS_DIR/ptau_1.ptau $ARTIFACTS_DIR/ptau.ptau -v
      mv $ARTIFACTS_DIR/ptau.ptau $ARTIFACTS_DIR/ptau
  fi
  
  # generate the trusted setup
  NAME=$(basename $C .circom)
  R1CS=$ARTIFACTS_DIR/$NAME.r1cs
  $SNARKJS groth16 setup $R1CS $ARTIFACTS_DIR/ptau $ARTIFACTS_DIR/$NAME\_pkey.zkey
  
  # export the verification key
  $SNARKJS zkey export verificationkey $ARTIFACTS_DIR/$NAME\_pkey.zkey $ARTIFACTS_DIR/$NAME\_vkey.json
  
  # mv wasm from $ARTIFACTS/$NAME_js/$NAME.wasm to $ARTIFACTS/$NAME.wasm
  if [ -f "$ARTIFACTS_DIR/$NAME\_js/$NAME.wasm" ]; then
    cp $ARTIFACTS_DIR/$NAME\_js/$NAME.wasm $ARTIFACTS_DIR/$NAME.wasm
  fi
done
  
# clean up
rm -rf ./node_modules package-lock.json package.json
