package lnwallet_test

import (
	"testing"

	"github.com/decred/dcrlnd/lnwallet"
)

// TestStaticFeeEstimator checks that the StaticFeeEstimator
// returns the expected fee rate.
func TestStaticFeeEstimator(t *testing.T) {
	t.Parallel()

	const feePerKw = lnwallet.FeePerKBFloor

	feeEstimator := lnwallet.NewStaticFeeEstimator(feePerKw, 0)
	if err := feeEstimator.Start(); err != nil {
		t.Fatalf("unable to start fee estimator: %v", err)
	}
	defer feeEstimator.Stop()

	feeRate, err := feeEstimator.EstimateFeePerKB(6)
	if err != nil {
		t.Fatalf("unable to get fee rate: %v", err)
	}

	if feeRate != feePerKw {
		t.Fatalf("expected fee rate %v, got %v", feePerKw, feeRate)
	}
}
