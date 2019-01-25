package lnwallet

import (
	"github.com/decred/dcrd/dcrutil"
	//"github.com/decred/dcrwallet/wallet/txrules" // TODO(decred): Uncomment when ported
)

// lnTxVersion is the version that transactions need to be defined to use so
// that they are usable as ln transactions.
const lnTxVersion uint16 = 2

// DefaultDustLimit is used to calculate the dust HTLC amount which will be
// send to other node during funding process.
func DefaultDustLimit() dcrutil.Amount {
	// TODO(decred): Correct size, implement txrules function, and use
	// p2sh size, not p2wsh.
	//return txrules.GetDustThreshold(P2WSHSize, txrules.DefaultRelayFeePerKb)
	return 248
}
