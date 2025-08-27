package test

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/z-ircuits/utils"
)

const (
	wasmFile = "../artifacts/ballot_checker_test.wasm"
	zkeyFile = "../artifacts/ballot_checker_test_pkey.zkey"
	vkeyFile = "../artifacts/ballot_checker_test_vkey.json"
)

// padToEight returns a slice of length 8, copying the caller‑supplied values
// and zero‑filling the remainder (or truncating if more than 8).
func padToEight(vals []int64) []int64 {
	out := make([]int64, 8)
	copy(out, vals)
	return out
}

// ballotToStrings converts an int64 slice to the string slice expected by the
// circom circuit.
func ballotToStrings(vals []int64) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strconv.FormatInt(v, 10)
	}
	return out
}

func TestBallotChecker(t *testing.T) {
	type tc struct {
		name         string
		fields       []int64 // raw field values (<= 8 non‑zero entries)
		maxCount     int     // logical field count provided by the ballot
		forceUnique  bool    // uniqueness flag
		maxValue     int
		minValue     int
		maxTotalCost int
		minTotalCost int
		costExp      int
		expectPass   bool
	}

	cases := []tc{
		{
			name:         "Simple 5‑star rating – valid",
			fields:       []int64{3, 2, 5},
			maxCount:     3,
			forceUnique:  true,
			maxValue:     5,
			minValue:     0,
			maxTotalCost: 15,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   true,
		},
		{
			name:         "Duplicate values with uniqueness required – invalid",
			fields:       []int64{3, 3, 1},
			maxCount:     3,
			forceUnique:  true,
			maxValue:     5,
			minValue:     0,
			maxTotalCost: 16,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   false,
		},
		{
			name:         "Maxvalue is correctly verified and maxTotalCost=0 is ignored – valid",
			fields:       []int64{50, 49, 48},
			maxCount:     3,
			forceUnique:  false,
			maxValue:     50,
			minValue:     0,
			maxTotalCost: 0,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   true,
		},
		{
			name:         "Value exceeds maxValue – invalid",
			fields:       []int64{13, 0, 0},
			maxCount:     3,
			forceUnique:  false,
			maxValue:     12,
			minValue:     0,
			maxTotalCost: 15,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   false,
		},
		{
			name:         "Value underflows minValue – invalid",
			fields:       []int64{1, 0, 0},
			maxCount:     3,
			forceUnique:  false,
			maxValue:     11,
			minValue:     5,
			maxTotalCost: 1000,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   false,
		},
		{
			name:         "Quadratic voting cost within limit – valid",
			fields:       []int64{2, 2, 2}, // cost = 4+4+4 = 12
			maxCount:     3,
			forceUnique:  false,
			maxValue:     4,
			minValue:     0,
			maxTotalCost: 12,
			minTotalCost: 0,
			costExp:      2,
			expectPass:   true,
		},
		{
			name:         "Quadratic voting cost exceeds limit – invalid",
			fields:       []int64{3, 2, 1}, // cost = 9+4+1 = 14 > 13
			maxCount:     3,
			forceUnique:  false,
			maxValue:     4,
			minValue:     0,
			maxTotalCost: 13,
			minTotalCost: 0,
			costExp:      2,
			expectPass:   false,
		},
		{
			name:         "MinTotalCost not reached – invalid",
			fields:       []int64{2, 0, 0}, // cost = 4 < 5
			maxCount:     3,
			forceUnique:  false,
			maxValue:     4,
			minValue:     0,
			maxTotalCost: 20,
			minTotalCost: 5,
			costExp:      2,
			expectPass:   false,
		},
		{
			name:         "Duplicates allowed when uniqueness off – valid",
			fields:       []int64{5, 5, 0},
			maxCount:     3,
			forceUnique:  false,
			maxValue:     5,
			minValue:     0,
			maxTotalCost: 15,
			minTotalCost: 0,
			costExp:      1,
			expectPass:   true,
		},
		{
			name:         "Approval voting – exactly 3 of 6 chosen – valid",
			fields:       []int64{1, 0, 1, 0, 1, 0},
			maxCount:     6,
			forceUnique:  false,
			maxValue:     1,
			minValue:     0,
			maxTotalCost: 3,
			minTotalCost: 3,
			costExp:      1,
			expectPass:   true,
		},
		{
			name:         "Approval voting – choose 4 out of 6 (exceeds limit) – invalid",
			fields:       []int64{1, 1, 1, 1, 0, 0}, // cost 4 > 3
			maxCount:     6,
			forceUnique:  false,
			maxValue:     1,
			minValue:     0,
			maxTotalCost: 3,
			minTotalCost: 3,
			costExp:      1,
			expectPass:   false,
		},
		{
			name:         "Ranked‑choice voting – unique ranks 1..3 – valid",
			fields:       []int64{1, 2, 3}, // sum = 6
			maxCount:     3,
			forceUnique:  true,
			maxValue:     3,
			minValue:     1,
			maxTotalCost: 6,
			minTotalCost: 6,
			costExp:      1,
			expectPass:   true,
		},
		{
			name:         "Ranked‑choice voting – duplicate rank – invalid",
			fields:       []int64{1, 1, 2},
			maxCount:     3,
			forceUnique:  true,
			maxValue:     3,
			minValue:     1,
			maxTotalCost: 6,
			minTotalCost: 6,
			costExp:      1,
			expectPass:   false,
		},
		{
			name:         "All zeros but minTotalCost positive – invalid",
			fields:       []int64{0, 0, 0},
			maxCount:     3,
			forceUnique:  false,
			maxValue:     5,
			minValue:     0,
			maxTotalCost: 10,
			minTotalCost: 1,
			costExp:      1,
			expectPass:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := qt.New(t)

			// Pad or truncate the ballot to exactly eight positions.
			padded := padToEight(tc.fields)

			// Force‑uniqueness flag as string (circom expects 0/1, not bool).
			uniq := "0"
			if tc.forceUnique {
				uniq = "1"
			}

			inputs := map[string]any{
				"fields":           ballotToStrings(padded),
				"num_fields":       strconv.Itoa(tc.maxCount),
				"unique_values":    uniq,
				"max_value":        strconv.Itoa(tc.maxValue),
				"min_value":        strconv.Itoa(tc.minValue),
				"max_value_sum":    strconv.Itoa(tc.maxTotalCost),
				"min_value_sum":    strconv.Itoa(tc.minTotalCost),
				"cost_exponent":    strconv.Itoa(tc.costExp),
				"weight":           "0",
				"cost_from_weight": "0",
			}

			bInputs, err := json.MarshalIndent(inputs, "  ", "  ")
			c.Assert(err, qt.IsNil)

			log.Printf("\n[%s] Inputs:\n%s\n", tc.name, string(bInputs))

			proofData, pubSignals, err := utils.CompileAndGenerateProof(bInputs, wasmFile, zkeyFile)

			if tc.expectPass {
				// Expect success in both proof generation and verification.
				c.Assert(err, qt.IsNil)

				vkey, err := os.ReadFile(vkeyFile)
				c.Assert(err, qt.IsNil)

				err = utils.VerifyProof(proofData, pubSignals, vkey)
				c.Assert(err, qt.IsNil)
			} else {
				// Failure is acceptable at either stage for negative tests.
				if err == nil {
					vkey, err2 := os.ReadFile(vkeyFile)
					c.Assert(err2, qt.IsNil)
					err = utils.VerifyProof(proofData, pubSignals, vkey)
				}
				c.Assert(err, qt.Not(qt.IsNil))
			}
		})
	}
}
