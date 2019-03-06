package zpay32

import (
	"fmt"
	"strconv"

	"github.com/decred/dcrlnd/lnwire"
)

var (
	// toMAt is a map from a unit to a function that converts an amount
	// of that unit to MilliAtoms.
	toMAt = map[byte]func(uint64) (lnwire.MilliAtom, error){
		'm': mDcrToMAt,
		'u': uDcrToMAt,
		'n': nDcrToMAt,
		'p': pDcrToMAt,
	}

	// fromMAt is a map from a unit to a function that converts an amount
	// in MilliAtoms to an amount of that unit.
	fromMAt = map[byte]func(lnwire.MilliAtom) (uint64, error){
		'm': mAtToMDcr,
		'u': mAtToUDcr,
		'n': mAtToNDcr,
		'p': mAtToPDcr,
	}
)

// mDcrToMAt converts the given amount in milliDCR to MilliAtoms.
func mDcrToMAt(m uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(m) * 100000000, nil
}

// uDcrToMAt converts the given amount in microDCR to MilliAtoms.
func uDcrToMAt(u uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(u * 100000), nil
}

// nDcrToMAt converts the given amount in nanoDCR to MilliAtoms.
func nDcrToMAt(n uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(n * 100), nil
}

// pDcrToMAt converts the given amount in picoDCR to MilliAtoms.
func pDcrToMAt(p uint64) (lnwire.MilliAtom, error) {
	if p < 10 {
		return 0, fmt.Errorf("minimum amount is 10p")
	}
	if p%10 != 0 {
		return 0, fmt.Errorf("amount %d pDCR not expressible in mAt",
			p)
	}
	return lnwire.MilliAtom(p / 10), nil
}

// mAtToMDcr converts the given amount in MilliAtoms to milliDCR.
func mAtToMDcr(mat lnwire.MilliAtom) (uint64, error) {
	if mat%100000000 != 0 {
		return 0, fmt.Errorf("%d mAt not expressible "+
			"in mDCR", mat)
	}
	return uint64(mat / 100000000), nil
}

// mAtToUDcr converts the given amount in MilliAtoms to microDCR.
func mAtToUDcr(msat lnwire.MilliAtom) (uint64, error) {
	if msat%100000 != 0 {
		return 0, fmt.Errorf("%d msat not expressible "+
			"in uBTC", msat)
	}
	return uint64(msat / 100000), nil
}

// mAtToNDcr converts the given amount in MilliAtoms to nanoDCR.
func mAtToNDcr(mat lnwire.MilliAtom) (uint64, error) {
	if mat%100 != 0 {
		return 0, fmt.Errorf("%d mAt not expressible in nDCR", mat)
	}
	return uint64(mat / 100), nil
}

// mAtToPDcr converts the given amount in MilliAtoms to picoDCR.
func mAtToPDcr(mat lnwire.MilliAtom) (uint64, error) {
	return uint64(mat * 10), nil
}

// decodeAmount returns the amount encoded by the provided string in
// MilliAtom.
func decodeAmount(amount string) (lnwire.MilliAtom, error) {
	if len(amount) < 1 {
		return 0, fmt.Errorf("amount must be non-empty")
	}

	// If last character is a digit, then the amount can just be
	// interpreted as BTC.
	char := amount[len(amount)-1]
	digit := char - '0'
	if digit >= 0 && digit <= 9 {
		btc, err := strconv.ParseUint(amount, 10, 64)
		if err != nil {
			return 0, err
		}
		return lnwire.MilliAtom(btc) * mAtPerDcr, nil
	}

	// If not a digit, it must be part of the known units.
	conv, ok := toMAt[char]
	if !ok {
		return 0, fmt.Errorf("unknown multiplier %c", char)
	}

	// Known unit.
	num := amount[:len(amount)-1]
	if len(num) < 1 {
		return 0, fmt.Errorf("number must be non-empty")
	}

	am, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, err
	}

	return conv(am)
}

// encodeAmount encodes the provided MilliAtom amount using as few characters
// as possible.
func encodeAmount(mat lnwire.MilliAtom) (string, error) {
	if mat < 0 {
		return "", fmt.Errorf("amount must be positive: %v", mat)
	}

	// If possible to express in DCR, that will always be the shortest
	// representation.
	if mat%mAtPerDcr == 0 {
		return strconv.FormatInt(int64(mat/mAtPerDcr), 10), nil
	}

	// Should always be expressible in pico DCR.
	pico, err := fromMAt['p'](mat)
	if err != nil {
		return "", fmt.Errorf("unable to express %d mAt as pDCR: %v",
			mat, err)
	}
	shortened := strconv.FormatUint(pico, 10) + "p"
	for unit, conv := range fromMAt {
		am, err := conv(mat)
		if err != nil {
			// Not expressible using this unit.
			continue
		}

		// Save the shortest found representation.
		str := strconv.FormatUint(am, 10) + string(unit)
		if len(str) < len(shortened) {
			shortened = str
		}
	}

	return shortened, nil
}
