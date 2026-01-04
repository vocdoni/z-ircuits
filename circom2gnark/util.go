package circom2gnark

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// stringToBigInt converts a decimal or hex string to a big.Int.
func stringToBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	bi := new(big.Int)
	_, ok := bi.SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("failed to parse big.Int from string: %s", s)
	}
	return bi, nil
}

func stringToBytesWithSize(s string, size int) ([]byte, error) {
	var b []byte
	if strings.HasPrefix(s, "0x") {
		var err error
		b, err = hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex string: %v", err)
		}
	} else {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, err
		}
		b = bi.Bytes()
	}
	// left-pad with zeros
	if len(b) > size {
		return nil, fmt.Errorf("bytes size exceeds expected size: got %d, want <= %d", len(b), size)
	}
	if len(b) < size {
		padding := make([]byte, size-len(b))
		b = append(padding, b...)
	}
	return b, nil
}

// stringToG1BLS converts coordinates into a BLS12-377 G1 point.
func stringToG1BLS(h []string) (*bls12377.G1Affine, error) {
	if len(h) < 2 {
		return nil, fmt.Errorf("not enough data for stringToG1BLS")
	}
	const coordBytes = 48
	hexa := len(h[0]) > 1 && strings.HasPrefix(h[0], "0x")
	var b []byte
	if hexa {
		for i := 0; i < len(h); i++ {
			dec, err := hex.DecodeString(strings.TrimPrefix(h[i], "0x"))
			if err != nil {
				return nil, err
			}
			b = append(b, leftPadBytes(dec, coordBytes)...)
		}
	} else {
		for i := 0; i < len(h); i++ {
			dec, err := stringToBytesWithSize(h[i], coordBytes)
			if err != nil {
				return nil, err
			}
			b = append(b, dec...)
		}
	}
	p := new(bls12377.G1Affine)
	if err := p.Unmarshal(b); err != nil {
		return nil, err
	}
	return p, nil
}

// stringToG2BLS converts coordinates into a BLS12-377 G2 point.
func stringToG2BLS(h [][]string) (*bls12377.G2Affine, error) {
	if len(h) < 2 {
		return nil, fmt.Errorf("not enough data for stringToG2BLS")
	}
	const coordBytes = 48
	hexa := len(h[0][0]) > 1 && strings.HasPrefix(h[0][0], "0x")
	var b []byte
	if hexa {
		for i := 0; i < len(h); i++ {
			for j := 0; j < len(h[i]); j++ {
				dec, err := hex.DecodeString(strings.TrimPrefix(h[i][j], "0x"))
				if err != nil {
					return nil, err
				}
				b = append(b, leftPadBytes(dec, coordBytes)...)
			}
		}
	} else {
		parts := []string{h[0][1], h[0][0], h[1][1], h[1][0]}
		for _, part := range parts {
			dec, err := stringToBytesWithSize(part, coordBytes)
			if err != nil {
				return nil, err
			}
			b = append(b, dec...)
		}
	}
	p := new(bls12377.G2Affine)
	if err := p.Unmarshal(b); err != nil {
		return nil, err
	}
	return p, nil
}

// leftPadBytes pads a byte slice to the desired length with leading zeros.
func leftPadBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padding := make([]byte, size-len(b))
	return append(padding, b...)
}
