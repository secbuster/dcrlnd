package lnwallet

import (
	"context"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
)

const (
	// FeePerKwFloor is the lowest fee rate in sat/kw that we should use for
	// determining transaction fees.
	FeePerKwFloor SatPerKWeight = 253
)

// SatPerKVByte represents a fee rate in sat/kb.
type SatPerKVByte dcrutil.Amount

// FeeForVSize calculates the fee resulting from this fee rate and the given
// vsize in vbytes.
func (s SatPerKVByte) FeeForVSize(vbytes int64) dcrutil.Amount {
	return dcrutil.Amount(s) * dcrutil.Amount(vbytes) / 1000
}

// FeePerKWeight converts the current fee rate from sat/kb to sat/kw.
func (s SatPerKVByte) FeePerKWeight() SatPerKWeight {
	return SatPerKWeight(s / blockchain.WitnessScaleFactor)
}

// SatPerKWeight represents a fee rate in sat/kw.
type SatPerKWeight dcrutil.Amount

// TODO(decred): No weight...
// FeeForWeight calculates the fee resulting from this fee rate and the given
// weight in weight units (wu).
func (s SatPerKWeight) FeeForWeight(wu int64) dcrutil.Amount {
	// The resulting fee is rounded down, as specified in BOLT#03.
	return dcrutil.Amount(s) * dcrutil.Amount(wu) / 1000
}

// FeePerKVByte converts the current fee rate from sat/kw to sat/kb.
func (s SatPerKWeight) FeePerKVByte() SatPerKVByte {
	return SatPerKVByte(s * blockchain.WitnessScaleFactor)
}

// FeeEstimator provides the ability to estimate on-chain transaction fees for
// various combinations of transaction sizes and desired confirmation time
// (measured by number of blocks).
type FeeEstimator interface {
	// EstimateFeePerByte takes in a target for the number of blocks until
	// an initial confirmation and returns the estimated fee expressed in
	// atoms/byte.
	EstimateFeePerByte(numBlocks uint32) (dcrutil.Amount, error)

	// Start signals the FeeEstimator to start any processes or goroutines
	// it needs to perform its duty.
	Start() error

	// Stop stops any spawned goroutines and cleans up the resources used
	// by the fee estimator.
	Stop() error

	// RelayFeePerKW returns the minimum fee rate required for transactions
	// to be relayed. This is also the basis for calculation of the dust
	// limit.
	RelayFeePerKW() SatPerKWeight
}

// StaticFeeEstimator will return a static value for all fee calculation
// requests. It is designed to be replaced by a proper fee calculation
// implementation. The fees are not accessible directly, because changing them
// would not be thread safe.
type StaticFeeEstimator struct {
	// TODO(decred): atoms-per-byte
	// feePerKW is the static fee rate in satoshis-per-vbyte that will be
	// returned by this fee estimator.
	feePerKW SatPerKWeight

	// relayFee is the minimum fee rate required for transactions to be
	// relayed.
	relayFee SatPerKWeight
}

// NewStaticFeeEstimator returns a new static fee estimator instance.
func NewStaticFeeEstimator(feePerKW,
	relayFee SatPerKWeight) *StaticFeeEstimator {

	return &StaticFeeEstimator{
		feePerKW: feePerKW,
		relayFee: relayFee,
	}
}

// TODO(decred): EstimateFeePerByte
//
// EstimateFeePerKW will return a static value for fee calculations.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error) {
	return e.feePerKW, nil
}

// TODO(decred): Update for no weighting in dcr
//
// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) RelayFeePerKW() SatPerKWeight {
	return e.relayFee
}

// Start signals the FeeEstimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) Start() error {
	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) Stop() error {
	return nil
}

// A compile-time assertion to ensure that StaticFeeEstimator implements the
// FeeEstimator interface.
var _ FeeEstimator = (*StaticFeeEstimator)(nil)

// DcrdFeeEstimator is an implementation of the FeeEstimator interface backed
// by the RPC interface of an active dcrd node. This implementation will proxy
// any fee estimation requests to dcrd's RPC interface.
type DcrdFeeEstimator struct {
	// TODO(decred): Update for no weighting in dcr and atoms per byte
	//
	// fallbackFeePerKW is the fall back fee rate in sat/kw that is returned
	// if the fee estimator does not yet have enough data to actually
	// produce fee estimates.
	fallbackFeePerKW SatPerKWeight

	// TODO(decred): Update for no weighting in dcr and atoms per byte
	//
	// minFeePerKW is the minimum fee, in sat/kw, that we should enforce.
	// This will be used as the default fee rate for a transaction when the
	// estimated fee rate is too low to allow the transaction to propagate
	// through the network.
	minFeePerKW SatPerKWeight

	dcrdConn *rpcclient.Client
}

// TODO(decred): Update for no weighting in dcr and atoms per byte
//
// NewDcrdFeeEstimator creates a new DcrdFeeEstimator given a fully populated
// rpc config that is able to successfully connect and authenticate with the
// dcrd node, and also a fall back fee rate. The fallback fee rate is used in
// the occasion that the estimator has insufficient data, or returns zero for a
// fee estimate.
func NewDcrdFeeEstimator(rpcConfig rpcclient.ConnConfig,
	fallBackFeeRate SatPerKWeight) (*DcrdFeeEstimator, error) {

	rpcConfig.DisableConnectOnNew = true
	rpcConfig.DisableAutoReconnect = false
	chainConn, err := rpcclient.New(&rpcConfig, nil)
	if err != nil {
		return nil, err
	}

	return &DcrdFeeEstimator{
		fallbackFeePerKW: fallBackFeeRate,
		dcrdConn:         chainConn,
	}, nil
}

// Start signals the FeeEstimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) Start() error {
	ctx := context.Background()
	if err := b.dcrdConn.Connect(ctx, true); err != nil {
		return err
	}

	// Once the connection to the backend node has been established, we'll
	// query it for its minimum relay fee.
	info, err := b.dcrdConn.GetInfo()
	if err != nil {
		return err
	}

	relayFee, err := dcrutil.NewAmount(info.RelayFee)
	if err != nil {
		return err
	}

	// The fee rate is expressed in sat/kb, so we'll manually convert it to
	// our desired sat/kw rate.
	minRelayFeePerKw := SatPerKVByte(relayFee).FeePerKWeight()

	// By default, we'll use the backend node's minimum relay fee as the
	// minimum fee rate we'll propose for transacations. However, if this
	// happens to be lower than our fee floor, we'll enforce that instead.
	b.minFeePerKW = minRelayFeePerKw
	if b.minFeePerKW < FeePerKwFloor {
		b.minFeePerKW = FeePerKwFloor
	}

	walletLog.Debugf("Using minimum fee rate of %v sat/kw",
		int64(b.minFeePerKW))

	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) Stop() error {
	b.dcrdConn.Shutdown()

	return nil
}

// TODO(decred): Update for no weighting in dcr and atoms per byte
//
// EstimateFeePerKW takes in a target for the number of blocks until an initial
// confirmation and returns the estimated fee expressed in sat/kw.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) EstimateFeePerKW(numBlocks uint32) (SatPerKWeight, error) {
	feeEstimate, err := b.fetchEstimate(numBlocks)
	switch {
	// If the estimator doesn't have enough data, or returns an error, then
	// to return a proper value, then we'll return the default fall back
	// fee rate.
	case err != nil:
		walletLog.Errorf("unable to query estimator: %v", err)
		fallthrough

	case feeEstimate == 0:
		return b.fallbackFeePerKW, nil
	}

	return feeEstimate, nil
}

// TODO(decred): Update for no weighting in dcr and atoms per byte
//
// RelayFeePerKW returns the minimum fee rate required for transactions to be
// relayed.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) RelayFeePerKW() SatPerKWeight {
	return b.minFeePerKW
}

// fetchEstimate returns a fee estimate for a transaction to be confirmed in
// confTarget blocks. The estimate is returned in sat/kw.
func (b *DcrdFeeEstimator) fetchEstimate(confTarget uint32) (SatPerKWeight, error) {
	// TODO(decred): Implement fee estimation.
	//
	// First, we'll fetch the estimate for our confirmation target.
	dcrPerKB, err := b.dcrdConn.EstimateFee(int64(confTarget))
	if err != nil {
		return 0, err
	}

	// TODO(decred): Update for no weighting in dcr and atoms per byte
	//
	// Next, we'll convert the returned value to satoshis, as it's
	// currently returned in DCR.
	satPerKB, err := dcrutil.NewAmount(dcrPerKB)
	if err != nil {
		return 0, err
	}

	// Since we use fee rates in sat/kw internally, we'll convert the
	// estimated fee rate from its sat/kb representation to sat/kw.
	satPerKw := SatPerKVByte(satPerKB).FeePerKWeight()

	// Finally, we'll enforce our fee floor.
	if satPerKw < b.minFeePerKW {
		walletLog.Debugf("Estimated fee rate of %v sat/kw is too low, "+
			"using fee floor of %v sat/kw instead", satPerKw,
			b.minFeePerKW)
		satPerKw = b.minFeePerKW
	}

	walletLog.Debugf("Returning %v sat/kw for conf target of %v",
		int64(satPerKw), confTarget)

	return satPerKw, nil
}

// A compile-time assertion to ensure that DcrdFeeEstimator implements the
// FeeEstimator interface.
var _ FeeEstimator = (*DcrdFeeEstimator)(nil)
