// +build dev

package lookout_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/keychain"
	"github.com/decred/dcrlnd/lnwallet"
	"github.com/decred/dcrlnd/lnwire"
	"github.com/decred/dcrlnd/watchtower/blob"
	"github.com/decred/dcrlnd/watchtower/lookout"
	"github.com/decred/dcrlnd/watchtower/wtdb"
)

const csvDelay uint32 = 144

var (
	revPrivBytes = []byte{
		0x8f, 0x4b, 0x51, 0x83, 0xa9, 0x34, 0xbd, 0x5f,
		0x74, 0x6c, 0x9d, 0x5c, 0xae, 0x88, 0x2d, 0x31,
		0x06, 0x90, 0xdd, 0x8c, 0x9b, 0x31, 0xbc, 0xd1,
		0x78, 0x91, 0x88, 0x2a, 0xf9, 0x74, 0xa0, 0xef,
	}

	toLocalPrivBytes = []byte{
		0xde, 0x17, 0xc1, 0x2f, 0xdc, 0x1b, 0xc0, 0xc6,
		0x59, 0x5d, 0xf9, 0xc1, 0x3e, 0x89, 0xbc, 0x6f,
		0x01, 0x85, 0x45, 0x76, 0x26, 0xce, 0x9c, 0x55,
		0x3b, 0xc9, 0xec, 0x3d, 0xd8, 0x8b, 0xac, 0xa8,
	}

	toRemotePrivBytes = []byte{
		0x28, 0x59, 0x6f, 0x36, 0xb8, 0x9f, 0x19, 0x5d,
		0xcb, 0x07, 0x48, 0x8a, 0xe5, 0x89, 0x71, 0x74,
		0x70, 0x4c, 0xff, 0x1e, 0x9c, 0x00, 0x93, 0xbe,
		0xe2, 0x2e, 0x68, 0x08, 0x4c, 0xb4, 0x0f, 0x4f,
	}
)

type mockSigner struct {
	index uint32
	keys  map[keychain.KeyLocator]*secp256k1.PrivateKey
}

func newMockSigner() *mockSigner {
	return &mockSigner{
		keys: make(map[keychain.KeyLocator]*secp256k1.PrivateKey),
	}
}

func (s *mockSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) ([]byte, error) {

	witnessScript := signDesc.WitnessScript
	privKey, ok := s.keys[signDesc.KeyDesc.KeyLocator]
	if !ok {
		panic("cannot sign w/ unknown key")
	}

	sig, err := txscript.RawTxInSignature(
		tx, signDesc.InputIndex,
		witnessScript, signDesc.HashType, privKey,
	)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}

func (s *mockSigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {
	return nil, nil
}

func (s *mockSigner) addPrivKey(privKey *secp256k1.PrivateKey) keychain.KeyLocator {
	keyLoc := keychain.KeyLocator{
		Index: s.index,
	}
	s.index++

	s.keys[keyLoc] = privKey

	return keyLoc
}

func TestJusticeDescriptor(t *testing.T) {
	const (
		localAmount  = dcrutil.Amount(100000)
		remoteAmount = dcrutil.Amount(200000)
		totalAmount  = localAmount + remoteAmount
	)
	netParams := &chaincfg.RegNetParams

	// Parse the key pairs for all keys used in the test.
	revSK, revPK := secp256k1.PrivKeyFromBytes(revPrivBytes)
	_, toLocalPK := secp256k1.PrivKeyFromBytes(toLocalPrivBytes)
	toRemoteSK, toRemotePK := secp256k1.PrivKeyFromBytes(toRemotePrivBytes)

	// Create the signer, and add the revocation and to-remote privkeys.
	signer := newMockSigner()
	var (
		revKeyLoc      = signer.addPrivKey(revSK)
		toRemoteKeyLoc = signer.addPrivKey(toRemoteSK)
	)

	// Construct the to-local witness script.
	toLocalScript, err := lnwallet.CommitScriptToSelf(
		csvDelay, toLocalPK, revPK,
	)
	if err != nil {
		t.Fatalf("unable to create to-local script: %v", err)
	}

	// Compute the to-local witness script hash.
	toLocalScriptHash, err := lnwallet.ScriptHashPkScript(toLocalScript)
	if err != nil {
		t.Fatalf("unable to create to-local witness script hash: %v", err)
	}

	// Compute the to-remote witness script hash.
	toRemoteScriptHash, err := lnwallet.CommitScriptUnencumbered(toRemotePK)
	if err != nil {
		t.Fatalf("unable to create to-remote script: %v", err)
	}

	// Construct the breaching commitment txn, containing the to-local and
	// to-remote outputs. We don't need any inputs for this test.
	breachTxn := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{},
		TxOut: []*wire.TxOut{
			{
				Value:    int64(localAmount),
				PkScript: toLocalScriptHash,
			},
			{
				Value:    int64(remoteAmount),
				PkScript: toRemoteScriptHash,
			},
		},
	}
	breachTxID := breachTxn.TxHash()

	// Compute the size estimate for our justice transaction.
	var sizeEstimate lnwallet.TxSizeEstimator
	sizeEstimate.AddP2PKHOutput()
	sizeEstimate.AddP2PKHOutput()
	sizeEstimate.AddCustomInput(lnwallet.ToLocalPenaltySigScriptSize)
	sizeEstimate.AddP2PKHInput()
	txSize := sizeEstimate.Size()

	// Create a session info so that simulate agreement of the sweep
	// parameters that should be used in constructing the justice
	// transaction.
	sessionInfo := &wtdb.SessionInfo{
		SweepFeeRate:  2000,
		RewardRate:    900000,
		RewardAddress: makeRandomP2PKHPkScript(),
	}

	// Given the total input amount and the size estimate, compute the
	// amount that should be swept for the victim and the amount taken as a
	// reward by the watchtower.
	sweepAmt, rewardAmt, err := sessionInfo.ComputeSweepOutputs(
		totalAmount, txSize,
	)
	if err != nil {
		t.Fatalf("unable to compute sweep outputs: %v", err)
	}

	// Begin to assemble the justice kit, starting with the sweep address,
	// pubkeys, and csv delay.
	justiceKit := &blob.JusticeKit{
		SweepAddress: makeRandomP2PKHPkScript(),
		CSVDelay:     csvDelay,
	}
	copy(justiceKit.RevocationPubKey[:], revPK.SerializeCompressed())
	copy(justiceKit.LocalDelayPubKey[:], toLocalPK.SerializeCompressed())
	copy(justiceKit.CommitToRemotePubKey[:], toRemotePK.SerializeCompressed())

	// Create a transaction spending from the outputs of the breach
	// transaction created earlier. The inputs are always ordered w/
	// to-local and then to-remote. The outputs are always added as the
	// sweep address then reward address.
	justiceTxn := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  breachTxID,
					Index: 0,
				},
				ValueIn: breachTxn.TxOut[0].Value,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  breachTxID,
					Index: 1,
				},
				ValueIn: breachTxn.TxOut[1].Value,
			},
		},
		TxOut: []*wire.TxOut{
			{

				Value:    int64(sweepAmt),
				PkScript: justiceKit.SweepAddress,
			},
			{

				Value:    int64(rewardAmt),
				PkScript: sessionInfo.RewardAddress,
			},
		},
	}

	// Create the sign descriptor used to sign for the to-local input.
	toLocalSignDesc := &lnwallet.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: revKeyLoc,
		},
		WitnessScript: toLocalScript,
		Output:        breachTxn.TxOut[0],
		InputIndex:    0,
		HashType:      txscript.SigHashAll,
	}

	// Create the sign descriptor used to sign for the to-remote input.
	toRemoteSignDesc := &lnwallet.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: toRemoteKeyLoc,
			PubKey:     toRemotePK,
		},
		WitnessScript: toRemoteScriptHash,
		Output:        breachTxn.TxOut[1],
		InputIndex:    1,
		HashType:      txscript.SigHashAll,
	}

	// Verify that our test justice transaction is sane.
	if err := blockchain.CheckTransactionSanity(justiceTxn, netParams); err != nil {
		t.Fatalf("justice txn is not sane: %v", err)
	}

	// Compute a DER-encoded signature for the to-local input.
	toLocalSigRaw, err := signer.SignOutputRaw(justiceTxn, toLocalSignDesc)
	if err != nil {
		t.Fatalf("unable to sign to-local input: %v", err)
	}

	// Compute the witness for the to-remote input. The first element is a
	// DER-encoded signature under the to-remote pubkey. The sighash flag is
	// also present, so we trim it.
	toRemoteWitness, err := lnwallet.CommitSpendNoDelay(
		signer, toRemoteSignDesc, justiceTxn,
	)
	if err != nil {
		t.Fatalf("unable to sign to-remote input: %v", err)
	}
	toRemoteSigRaw := toRemoteWitness[0][:len(toRemoteWitness[0])-1]

	// Convert the DER to-local sig into a fixed-size signature.
	toLocalSig, err := lnwire.NewSigFromRawSignature(toLocalSigRaw)
	if err != nil {
		t.Fatalf("unable to parse to-local signature: %v", err)
	}

	// Convert the DER to-remote sig into a fixed-size signature.
	toRemoteSig, err := lnwire.NewSigFromRawSignature(toRemoteSigRaw)
	if err != nil {
		t.Fatalf("unable to parse to-remote signature: %v", err)
	}

	// Complete our justice kit by copying the signatures into the payload.
	copy(justiceKit.CommitToLocalSig[:], toLocalSig[:])
	copy(justiceKit.CommitToRemoteSig[:], toRemoteSig[:])

	justiceDesc := &lookout.JusticeDescriptor{
		BreachedCommitTx: breachTxn,
		SessionInfo:      sessionInfo,
		JusticeKit:       justiceKit,
		NetParams:        netParams,
	}

	// Construct a breach punisher that will feed published transactions
	// over the buffered channel.
	publications := make(chan *wire.MsgTx, 1)
	punisher := lookout.NewBreachPunisher(&lookout.PunisherConfig{
		PublishTx: func(tx *wire.MsgTx) error {
			publications <- tx
			return nil
		},
	})

	// Exact retribution on the offender. If no error is returned, we expect
	// the justice transaction to be published via the channel.
	err = punisher.Punish(justiceDesc, nil)
	if err != nil {
		t.Fatalf("unable to punish breach: %v", err)
	}

	// Retrieve the published justice transaction.
	var wtJusticeTxn *wire.MsgTx
	select {
	case wtJusticeTxn = <-publications:
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("punisher did not publish justice txn")
	}

	// Construct the test's to-local witness.
	wstack0 := make([][]byte, 3)
	wstack0[0] = append(toLocalSigRaw, byte(txscript.SigHashAll))
	wstack0[1] = []byte{1}
	wstack0[2] = toLocalScript
	justiceTxn.TxIn[0].SignatureScript, err = lnwallet.WitnessStackToSigScript(wstack0)
	if err != nil {
		t.Fatalf("error assembling wstack0: %v", err)
	}

	// Construct the test's to-remote witness.
	wstack1 := make([][]byte, 2)
	wstack1[0] = append(toRemoteSigRaw, byte(txscript.SigHashAll))
	wstack1[1] = toRemotePK.SerializeCompressed()
	justiceTxn.TxIn[1].SignatureScript, err = lnwallet.WitnessStackToSigScript(wstack1)
	if err != nil {
		t.Fatalf("error assembling wstack1: %v", err)
	}

	// Assert that the watchtower derives the same justice txn.
	if !reflect.DeepEqual(justiceTxn, wtJusticeTxn) {
		t.Fatalf("expected justice txn: %v\ngot %v",
			spew.Sdump(justiceTxn),
			spew.Sdump(wtJusticeTxn))
	}
}
