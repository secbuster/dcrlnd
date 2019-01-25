package lnwallet

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/channeldb"
	"github.com/decred/dcrlnd/keychain"
	"github.com/decred/dcrlnd/lnwire"
	"github.com/decred/dcrlnd/shachain"
)

/**
* This file implements that different types of transactions used in the
* lightning protocol are created correctly. To do so, the tests use the test
* vectors defined in Appendix B & C of BOLT 03.
 */

// testContext contains the test parameters defined in Appendix B & C of the
// BOLT 03 spec.
type testContext struct {
	netParams *chaincfg.Params
	block1    *dcrutil.Block

	fundingInputPrivKey *secp256k1.PrivateKey
	localFundingPrivKey *secp256k1.PrivateKey
	localPaymentPrivKey *secp256k1.PrivateKey

	remoteFundingPubKey    *secp256k1.PublicKey
	localFundingPubKey     *secp256k1.PublicKey
	localRevocationPubKey  *secp256k1.PublicKey
	localPaymentPubKey     *secp256k1.PublicKey
	remotePaymentPubKey    *secp256k1.PublicKey
	localDelayPubKey       *secp256k1.PublicKey
	commitmentPoint        *secp256k1.PublicKey
	localPaymentBasePoint  *secp256k1.PublicKey
	remotePaymentBasePoint *secp256k1.PublicKey

	fundingChangeAddress dcrutil.Address
	fundingInputUtxo     *Utxo
	fundingInputTxOut    *wire.TxOut
	fundingTx            *dcrutil.Tx
	fundingOutpoint      wire.OutPoint
	shortChanID          lnwire.ShortChannelID

	htlcs []channeldb.HTLC

	localCsvDelay uint16
	fundingAmount dcrutil.Amount
	dustLimit     dcrutil.Amount
	feePerKW      dcrutil.Amount
}

// htlcDesc is a description used to construct each HTLC in each test case.
type htlcDesc struct {
	index           int
	remoteSigHex    string
	resolutionTxHex string
}

// getHTLC constructs an HTLC based on a configured HTLC with auxiliary data
// such as the remote signature from the htlcDesc. The partially defined HTLCs
// originate from the BOLT 03 spec and are contained in the test context.
func (tc *testContext) getHTLC(index int, desc *htlcDesc) (channeldb.HTLC, error) {
	signature, err := hex.DecodeString(desc.remoteSigHex)
	if err != nil {
		return channeldb.HTLC{}, fmt.Errorf(
			"Failed to parse serialized signature: %v", err)
	}

	htlc := tc.htlcs[desc.index]
	return channeldb.HTLC{
		Signature:     signature,
		RHash:         htlc.RHash,
		RefundTimeout: htlc.RefundTimeout,
		Amt:           htlc.Amt,
		OutputIndex:   int32(index),
		Incoming:      htlc.Incoming,
	}, nil
}

// newTestContext populates a new testContext struct with the constant
// parameters defined in the BOLT 03 spec. This may return an error if any of
// the serialized parameters cannot be parsed.
func newTestContext() (tc *testContext, err error) {
	tc = new(testContext)

	const genesisHash = "2ced94b4ae95bba344cfa043268732d230649c640f92dce2d9518823d3057cb0"
	if tc.netParams, err = tc.createNetParams(genesisHash); err != nil {
		return
	}

	const block1Hex = "06000000b07c05d3238851d9e2dc920f649c6430d232872643a0cf44a3bb95aeb494ed2c841706fbd326fb3584ac6ed18f2899189c2d20bae5031932dd8a004300c2dabc000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000ffff7f20204e0000000000000100000073010000e94c485c01000000cf1e86eb445c26a0000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300a0724e1809000000001976a9147e4765ae88ba9ad5c9e4715c484e90b34d358d5188ac00a0724e1809000000001976a91402fb1ac0137666d79165e13cecd403883615270788ac00a0724e1809000000001976a91469de627d3231b14228653dd09cba75eeb872754288ac00000000000000000100e057eb481b000000000000ffffffff0800002f646372642f00"
	if tc.block1, err = blockFromHex(block1Hex); err != nil {
		err = fmt.Errorf("Failed to parse serialized block: %v", err)
		return
	}

	// Key for decred's BlockOneLedgerRegNet address RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6
	const fundingInputPrivKeyHex = "fd79250838efa1c142e182d012004c541df2668014cc1758027d70069b2ef474"
	tc.fundingInputPrivKey, err = privkeyFromHex(fundingInputPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localFundingPrivKeyHex = "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749"
	tc.localFundingPrivKey, err = privkeyFromHex(localFundingPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localPaymentPrivKeyHex = "bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f274694491"
	tc.localPaymentPrivKey, err = privkeyFromHex(localPaymentPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localFundingPubKeyHex = "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
	tc.localFundingPubKey, err = pubkeyFromHex(localFundingPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	// Sanity check.
	if !tc.localFundingPrivKey.PubKey().IsEqual(tc.localFundingPubKey) {
		err = fmt.Errorf("Pubkey of localFundingPrivKey not the same as encoded")
		return
	}

	const remoteFundingPubKeyHex = "037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd5"
	tc.remoteFundingPubKey, err = pubkeyFromHex(remoteFundingPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localRevocationPubKeyHex = "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19"
	tc.localRevocationPubKey, err = pubkeyFromHex(localRevocationPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localPaymentPubKeyHex = "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"
	tc.localPaymentPubKey, err = pubkeyFromHex(localPaymentPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const remotePaymentPubKeyHex = "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b"
	tc.remotePaymentPubKey, err = pubkeyFromHex(remotePaymentPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localDelayPubKeyHex = "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c"
	tc.localDelayPubKey, err = pubkeyFromHex(localDelayPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const commitmentPointHex = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"
	tc.commitmentPoint, err = pubkeyFromHex(commitmentPointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localPaymentBasePointHex = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
	tc.localPaymentBasePoint, err = pubkeyFromHex(localPaymentBasePointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const remotePaymentBasePointHex = "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
	tc.remotePaymentBasePoint, err = pubkeyFromHex(remotePaymentBasePointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const fundingChangeAddressStr = "Rs8LovBHZfZmC4ShUicmExNWaivPm5cBtNN"
	tc.fundingChangeAddress, err = dcrutil.DecodeAddress(
		fundingChangeAddressStr)
	if err != nil {
		err = fmt.Errorf("Failed to parse address: %v", err)
		return
	}

	tc.fundingInputUtxo, tc.fundingInputTxOut, err = tc.extractFundingInput()
	if err != nil {
		return
	}

	const fundingTxHex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300a0724e1809000000001976a9147e4765ae88ba9ad5c9e4715c484e90b34d358d5188ac00a0724e1809000000001976a91402fb1ac0137666d79165e13cecd403883615270788ac00a0724e1809000000001976a91469de627d3231b14228653dd09cba75eeb872754288ac00000000000000000100e057eb481b000000000000ffffffff0800002f646372642f"
	if tc.fundingTx, err = txFromHex(fundingTxHex); err != nil {
		err = fmt.Errorf("Failed to parse serialized tx: %v", err)
		return
	}

	tc.fundingOutpoint = wire.OutPoint{
		Hash:  *tc.fundingTx.Hash(),
		Index: 0,
	}

	tc.shortChanID = lnwire.ShortChannelID{
		BlockHeight: 1,
		TxIndex:     0,
		TxPosition:  0,
	}

	htlcData := []struct {
		incoming    bool
		amount      lnwire.MilliSatoshi
		expiry      uint32
		preimage    string
		paymentHash PaymentHash
	}{
		{
			incoming: true,
			amount:   1000000,
			expiry:   500,
			preimage: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			incoming: true,
			amount:   2000000,
			expiry:   501,
			preimage: "0101010101010101010101010101010101010101010101010101010101010101",
		},
		{
			incoming: false,
			amount:   2000000,
			expiry:   502,
			preimage: "0202020202020202020202020202020202020202020202020202020202020202",
		},
		{
			incoming: false,
			amount:   3000000,
			expiry:   503,
			preimage: "0303030303030303030303030303030303030303030303030303030303030303",
		},
		{
			incoming: true,
			amount:   4000000,
			expiry:   504,
			preimage: "0404040404040404040404040404040404040404040404040404040404040404",
		},
	}

	tc.htlcs = make([]channeldb.HTLC, len(htlcData))
	for i, htlc := range htlcData {
		preimage, decodeErr := hex.DecodeString(htlc.preimage)
		if decodeErr != nil {
			err = fmt.Errorf("Failed to decode HTLC preimage: %v", decodeErr)
			return
		}

		tc.htlcs[i].RHash = chainhash.HashH(preimage)
		tc.htlcs[i].Amt = htlc.amount
		tc.htlcs[i].RefundTimeout = htlc.expiry
		tc.htlcs[i].Incoming = htlc.incoming
	}

	tc.localCsvDelay = 144
	tc.fundingAmount = 10000000
	tc.dustLimit = 546
	tc.feePerKW = 15000

	return
}

// createNetParams is used by newTestContext to construct new chain parameters
// as required by the BOLT 03 spec.
func (tc *testContext) createNetParams(genesisHashStr string) (*chaincfg.Params, error) {
	params := chaincfg.RegNetParams

	// Ensure regression net genesis block matches the one listed in BOLT spec.
	expectedGenesisHash, err := chainhash.NewHashFromStr(genesisHashStr)
	if err != nil {
		return nil, err
	}
	if !params.GenesisHash.IsEqual(expectedGenesisHash) {
		err = fmt.Errorf("Expected regression net genesis hash to be %s, "+
			"got %s", expectedGenesisHash, params.GenesisHash)
		return nil, err
	}

	return &params, nil
}

// extractFundingInput returns references to the transaction output of the
// coinbase transaction which is used to fund the channel in the test vectors.
func (tc *testContext) extractFundingInput() (*Utxo, *wire.TxOut, error) {
	expectedTxHashHex := "f94a4d807512f45842661cc7fdefebafd54cbc1338655bccd8e9821d06e402c4"
	expectedTxHash, err := chainhash.NewHashFromStr(expectedTxHashHex)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse transaction hash: %v", err)
	}

	tx, err := tc.block1.Tx(0)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get coinbase transaction from "+
			"block 1: %v", err)
	}
	txout := tx.MsgTx().TxOut[0]

	var expectedAmount int64 = 10000000000000
	if txout.Value != expectedAmount {
		return nil, nil, fmt.Errorf("Coinbase transaction output amount from "+
			"block 1 does not match expected output amount: "+
			"expected %v, got %v", expectedAmount, txout.Value)
	}
	if !tx.Hash().IsEqual(expectedTxHash) {
		return nil, nil, fmt.Errorf("Coinbase transaction hash from block 1 "+
			"does not match expected hash: expected %v, got %v", expectedTxHash,
			tx.Hash())
	}

	block1Utxo := Utxo{
		AddressType: WitnessPubKey,
		Value:       dcrutil.Amount(txout.Value),
		OutPoint: wire.OutPoint{
			Hash:  *tx.Hash(),
			Index: 0,
		},
		PkScript: txout.PkScript,
	}
	return &block1Utxo, txout, nil
}

// TestCommitmentAndHTLCTransactions checks the test vectors specified in
// BOLT 03, Appendix C. This deterministically generates commitment and second
// level HTLC transactions and checks that they match the expected values.
func TestCommitmentAndHTLCTransactions(t *testing.T) {
	t.Parallel()

	tc, err := newTestContext()
	if err != nil {
		t.Fatal(err)
	}

	// Generate random some keys that don't actually matter but need to be set.
	var (
		identityKey         *secp256k1.PublicKey
		localDelayBasePoint *secp256k1.PublicKey
	)
	generateKeys := []**secp256k1.PublicKey{
		&identityKey,
		&localDelayBasePoint,
	}
	for _, keyRef := range generateKeys {
		privkey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate new key: %v", err)
		}
		*keyRef = privkey.PubKey()
	}

	// Manually construct a new LightningChannel.
	channelState := channeldb.OpenChannel{
		ChanType:        channeldb.SingleFunder,
		ChainHash:       *tc.netParams.GenesisHash,
		FundingOutpoint: tc.fundingOutpoint,
		ShortChannelID:  tc.shortChanID,
		IsInitiator:     true,
		IdentityPub:     identityKey,
		LocalChanCfg: channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				DustLimit:        tc.dustLimit,
				MaxPendingAmount: lnwire.NewMSatFromSatoshis(tc.fundingAmount),
				MaxAcceptedHtlcs: MaxHTLCNumber,
			},
			CsvDelay: tc.localCsvDelay,
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: tc.localFundingPubKey,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: tc.localPaymentBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: tc.localPaymentBasePoint,
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: localDelayBasePoint,
			},
		},
		RemoteChanCfg: channeldb.ChannelConfig{
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: tc.remoteFundingPubKey,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: tc.remotePaymentBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: tc.remotePaymentBasePoint,
			},
		},
		Capacity:           tc.fundingAmount,
		RevocationProducer: shachain.NewRevocationProducer(shachain.ShaHash(zeroHash)),
	}
	signer := &mockSigner{
		privkeys: []*secp256k1.PrivateKey{
			tc.localFundingPrivKey, tc.localPaymentPrivKey,
		},
		netParams: tc.netParams,
	}

	// Construct a LightningChannel manually because we don't have nor need all
	// of the dependencies.
	channel := LightningChannel{
		channelState:  &channelState,
		Signer:        signer,
		localChanCfg:  &channelState.LocalChanCfg,
		remoteChanCfg: &channelState.RemoteChanCfg,
		netParams:     tc.netParams,
	}
	err = channel.createSignDesc()
	if err != nil {
		t.Fatalf("Failed to generate channel sign descriptor: %v", err)
	}
	channel.createStateHintObfuscator()

	// The commitmentPoint is technically hidden in the spec, but we need it to
	// generate the correct tweak.
	tweak := SingleTweakBytes(tc.commitmentPoint, tc.localPaymentBasePoint)
	keys := &CommitmentKeyRing{
		CommitPoint:         tc.commitmentPoint,
		LocalCommitKeyTweak: tweak,
		LocalHtlcKeyTweak:   tweak,
		LocalHtlcKey:        tc.localPaymentPubKey,
		RemoteHtlcKey:       tc.remotePaymentPubKey,
		DelayKey:            tc.localDelayPubKey,
		NoDelayKey:          tc.remotePaymentPubKey,
		RevocationKey:       tc.localRevocationPubKey,
	}

	// testCases encode the raw test vectors specified in Appendix C of BOLT 03.
	// TODO(decred) The stored hex txs need to be reviewed and documented somewhere.
	testCases := []struct {
		commitment              channeldb.ChannelCommitment
		htlcDescs               []htlcDesc
		expectedCommitmentTxHex string
		remoteSigHex            string
	}{
		{ // 0
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  7000000000,
				RemoteBalance: 3000000000,
				FeePerKw:      15000,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac6cba6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100fcab4b6cf8d06afe92f7d0494b030abdc43b7dde70bdfa1b35db25b425a2eeb00220426738f580538eddfca5a63b4e5e8636a569c5d97017e6e7a9188993bbaf14410148304502210084692d21148d19a81086512ab60486c15da6ea3765143ac5e372746ca2ec554602200c1f91f7a76a50d7ef00c4bfc25b1bca7632adc1fb506ccf80bf10df39e8626d01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304502210084692d21148d19a81086512ab60486c15da6ea3765143ac5e372746ca2ec554602200c1f91f7a76a50d7ef00c4bfc25b1bca7632adc1fb506ccf80bf10df39e8626d",
		},
		{ // 1
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      0,
			},
			htlcDescs: []htlcDesc{
				{ // 1,0
					index:           0,
					remoteSigHex:    "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000",
				},
				{ // 1,1
					index:           2,
					remoteSigHex:    "3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b",
					resolutionTxHex: "0200000001377b2a3b0021c75be6e54566d7d4b245b9080ae0750f2c6b6d317551a3e4641501000000000000000001d007000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1901483045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b014730440220538e3524110ee3434a168e1e160f646030322455480fc347e2560d7071bbe6df02203ddcf6767466fe2341ffbad779aac536db6d42f475eb7a97499f43fa33e0c5a501004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 1,2
					index:           1,
					remoteSigHex:    "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 1,3
					index:           3,
					remoteSigHex:    "3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554",
					resolutionTxHex: "0200000001377b2a3b0021c75be6e54566d7d4b245b9080ae0750f2c6b6d317551a3e4641503000000000000000001b80b000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554014830450221009314a8c4003df33594603787d9512ec47a3f31624332aac1466e65c09cd8ed1d02205b3a7cd02817f8d36957196f415c88b905fa2c67ae5463967f15098979f5e47a01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 1,4
					index:           4,
					remoteSigHex:    "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8007e803000000000000000017a914002ec21b1e6b5760f31a8bf7a3ade0c7f0755d6587d007000000000000000017a91418662f957b3994ad7ff1c1677fd764d20500b93c87d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ace0a06a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd948304502210091364f1a52940fbe72f95c720481a1a472682751c1b56e5e4d44e898576bede602201854dfdb5e8ec0d64851f6b0f6772aa6dfd65eadf40799f16988ca2994b1d14601473044022002490682d0cf4c9c41033eb2827338cff0ac1efa3bb3735da88d83e2687649cf0220588d3e3144ec6030e0b51c031c2dfc07005132d4b842395f022b9f0f7b46d25301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3044022002490682d0cf4c9c41033eb2827338cff0ac1efa3bb3735da88d83e2687649cf0220588d3e3144ec6030e0b51c031c2dfc07005132d4b842395f022b9f0f7b46d253",
		},
		{ // 2
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      647,
			},
			htlcDescs: []htlcDesc{
				{ // 2,0
					index:           0,
					remoteSigHex:    "30440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab343740",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb60000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab3437400147304402205999590b8a79fa346e003a68fd40366397119b2b0cdf37b149968d6bc6fbcc4702202b1e1fb5ab7864931caed4e732c359e0fe3d86a548b557be2246efb1708d579a012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000",
				},
				{ // 2,1
					index:           2,
					remoteSigHex:    "304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b0",
					resolutionTxHex: "0200000001dbd2756fdd8d91d147c60a4081eb1f5d81b8f89436a9bfc3da2822a54ce8f9cf01000000000000000001d306000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd190147304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b001483045022100b54740a6f4ebdd8b5acc8e7ad8fbc5ef83221c54850d66e7a112cb6e3c7a03e102201a20cc63c9b795618342a9e7e429286bf6c0e631133cef7a1374bed19d56ef3301004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 2,2
					index:           1,
					remoteSigHex:    "304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d833",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb6020000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d83301483045022100d50d067ca625d54e62df533a8f9291736678d0b86c28a61bb2a80cf42e702d6e02202373dde7e00218eacdafb9415fe0e1071beec1857d1af3c6a201a44cbc47c877012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 2,3
					index:           3,
					remoteSigHex:    "30450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d",
					resolutionTxHex: "0200000001dbd2756fdd8d91d147c60a4081eb1f5d81b8f89436a9bfc3da2822a54ce8f9cf03000000000000000001bb0a000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a014830450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d01483045022100f1aad0d2bc9c7461660fb68e83630024e7e81461893a59702a5223fedaae8a63022034aea1d91d32775ba0adcae62c4a6db3bf5f0da070217d58627964655e6dc46b01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 2,4
					index:           4,
					remoteSigHex:    "3045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f0",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb604000000000000000001da0d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f00147304402202d1a3c0d31200265d2a2def2753ead4959ae20b4083e19553acfffa5dfab60bf022020ede134149504e15b88ab261a066de49848411e15e70f9e6a5462aec2949f8f012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8007e803000000000000000017a914002ec21b1e6b5760f31a8bf7a3ade0c7f0755d6587d007000000000000000017a91418662f957b3994ad7ff1c1677fd764d20500b93c87d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac879f6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd747304402205e06b836257a2c1b8abe461ec8ecb46f290b3c19a57865c73d578a22f06e6f9002201fe9342f55df5572bec0f8404def23a85c9045f472e63c20154994313c93a20901463043021f7b1140e4b7acf818a02a84ec4c49fb3ba1d1e3b69b05446b924c7bc4cf90c702201b353f30de0a47ea9a175d0827c5db0781c397ca9f535d032af5c9e361bf0eec01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3043021f7b1140e4b7acf818a02a84ec4c49fb3ba1d1e3b69b05446b924c7bc4cf90c702201b353f30de0a47ea9a175d0827c5db0781c397ca9f535d032af5c9e361bf0eec",
		},
		{ // 3
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      648,
			},
			htlcDescs: []htlcDesc{
				{ // 3,0
					index:           2,
					remoteSigHex:    "3044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada8",
					resolutionTxHex: "020000000110390da2dfc5be5dd4c84a3ad316337589913f6fddf3db6284709f302b5d7c1700000000000000000001d206000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1801473044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada801473044022055c957eba009be2e8eb58b2f51649b13f2eb9d126a924369f18a150df0611c92022058065cbc167d03401e2cbcd82e693e4fe8b598bdd6f645de0dba9e94a88caf1b01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 3,1
					index:           1,
					remoteSigHex:    "3045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d4",
					resolutionTxHex: "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd10100000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d40147304402207679cf19790bea76a733d2fa0672bd43ab455687a068f815a3d237581f57139a0220683a1a799e102071c206b207735ca80f627ab83d6616b4bcd017c5d79ef3e7d0012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 3,2
					index:           3,
					remoteSigHex:    "3045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c2",
					resolutionTxHex: "020000000110390da2dfc5be5dd4c84a3ad316337589913f6fddf3db6284709f302b5d7c1702000000000000000001ba0a000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901483045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c2014730440220571ede175458a472b526bd35bb5ed0590d73218bcccc65a434ffb7b21ee7b458022070e5559e3dee762ef38465938baa1299ecae4556c607b73d038b94ba7c7fd25901004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 3,3
					index:           4,
					remoteSigHex:    "3044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f",
					resolutionTxHex: "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd103000000000000000001d90d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f0147304402200daf2eb7afd355b4caf6fb08387b5f031940ea29d1a9f35071288a839c9039e4022067201b562456e7948616c13acb876b386b511599b58ac1d94d127f91c50463a6012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8006d007000000000000000017a91418662f957b3994ad7ff1c1677fd764d20500b93c87d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac9c9f6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd847304402205dd364169ba5ebe13f8f9b85c5accb069b1d7557e48400dc5d1f4a79a08cf61a0220048aeca6adc58a887a96536616c2d237faca65c6c8f053dbf726a32e84288a39014730440220336373257a3579c9796779acd62855b2d9428e38bde88e34a930f53d84c59742022034788f3c1b5686915bfa27fe8618955f0b360e1c93d1181b6f59a5d3ac53586a01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30440220336373257a3579c9796779acd62855b2d9428e38bde88e34a930f53d84c59742022034788f3c1b5686915bfa27fe8618955f0b360e1c93d1181b6f59a5d3ac53586a",
		},
		{ // 4
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      2069,
			},
			htlcDescs: []htlcDesc{
				{ // 4,0
					index:           2,
					remoteSigHex:    "3045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f992",
					resolutionTxHex: "0200000001120c4adfb21f53c7406580d129f83d7061cbcd9925fab7004053ee6c7fe2506000000000000000000001a504000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1901483045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f99201473044022029861ebe02e9ee5e1ecaf9cb0c8bf17b3b63abcaf41a21c3f2183896dc9d0a61022074ee23effb71b7dae86f63f8d639f4edffc652344422283c7bc93f7258e52d6201004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 4,1
					index:           1,
					remoteSigHex:    "3045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f4",
					resolutionTxHex: "0200000001cdd89ae2becc198085cbe354f957cbfaef88f86990a6dd3ddc7a2ce0cbb3461d010000000000000000018b0800000000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ef7010000000000000100000000000000000000000000000000fd1801473044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf601473044022055ced5fb769834f73eee4c3eb5f42c2ee95af231be81ae8be4e7f10ce239f2ca022020537289328cd497ff6f8f59015d24bda936e62ed1c8f9dc331aefd190a5fbcb01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868",
				},
				{ // 4,2
					index:           3,
					remoteSigHex:    "3045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef18",
					resolutionTxHex: "0200000001120c4adfb21f53c7406580d129f83d7061cbcd9925fab7004053ee6c7fe25060020000000000000000018d08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901483045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef180147304402201175144a31e504e1f5020b4626ede718647d1289874af504e3180b5fdb215fa60220336c91e5b4bee21530862744eae00f13aff3b8515a014b39888445a92049503901004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 4,3
					index:           4,
					remoteSigHex:    "30450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c",
					resolutionTxHex: "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a03000000000000000001f2090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c0147304402202c3e14282b84b02705dfd00a6da396c9fe8a8bcb1d3fdb4b20a4feba09440e8b02202b058b39aa9b0c865b22095edcd9ff1f71bbfe20aa4993755e54d042755ed0d5012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8006d007000000000000000017a91418662f957b3994ad7ff1c1677fd764d20500b93c87d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88acd69c6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9473044022006648c7146ce8372f794fc73731659b134bd3b56cac459bd08ef327b293e94f902207d52343467711569af89cb024a8671991a120501d48e9537fa5f3a7f0cf1102501483045022100f5a3962ab385f52b55a0e227ef80fc60db93fa75bf4cee3c18512866ce9f413602203bcd91e9107d74a004eb32c550210a7b628e72f685ded781c22478020b792b9301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100f5a3962ab385f52b55a0e227ef80fc60db93fa75bf4cee3c18512866ce9f413602203bcd91e9107d74a004eb32c550210a7b628e72f685ded781c22478020b792b93",
		},
		{ // 5
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      2070,
			},
			htlcDescs: []htlcDesc{
				{ // 5,0
					index:           2,
					remoteSigHex:    "3045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f891",
					resolutionTxHex: "020000000192a62eae775f3b80c4ace4b93ddb59df85f9c6db27dee9df44c5d85d9a6eb5b100000000000000000001a504000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1901483045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f8910147304402207db296ee37d42ee46f1b512dcb05e3cb908b31e841eaf50ebddbbe5e612d89bc0220113ae5ef30950d61f762e7befb083a095ffef5621a22db304b48cca534dcb7a601004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 5,1
					index:           3,
					remoteSigHex:    "3044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf6",
					resolutionTxHex: "020000000192a62eae775f3b80c4ace4b93ddb59df85f9c6db27dee9df44c5d85d9a6eb5b1010000000000000000018d08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901473044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf601483045022100f9f12dd158566cec8001932834a4f621c861f7d54b22e3aaee1955256950e94b02203927c01ccb9b78086367a5e4fd045d4e30935ca88991345b8ada225f20ce1ca201004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 5,2
					index:           4,
					remoteSigHex:    "3045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a4",
					resolutionTxHex: "020000000112b0f746ca4c74cd579424e3110a8e75e1e00a24f4f37eb5cbc3bfdb9a83944d020000000000000000018b0800000000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ef7010000000000000100000000000000000000000000000000fd1901483045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef180147304402200405a71afc1e023e501c390770e4859e84601986975293fbdae165224a2a2f4802206a88efb0fa687a0372155bc1d1c9feddf11c1fc9b25751326973079090e29cc401004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8005d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac1c9d6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd8473044022027511236085145d8114f3b429937da433605d6e869713c1d324855eedd5202d902205dbf49c9dd494857004dea12a4ffb502282f0559511cf9987e2275e5e1ae05450147304402205534d0a9b7df74e4947ddc7ab4f87ef53a026eadbc8ede221ae28c94e92db11b022060f476e96d603fb705b4ada6b3303257a2a70fca9e0037b902f36369461ad0b501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402205534d0a9b7df74e4947ddc7ab4f87ef53a026eadbc8ede221ae28c94e92db11b022060f476e96d603fb705b4ada6b3303257a2a70fca9e0037b902f36369461ad0b5",
		},
		{ // 6
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      2194,
			},
			htlcDescs: []htlcDesc{
				{ // 6,0
					index:           2,
					remoteSigHex:    "30450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf44",
					resolutionTxHex: "0200000001e40a648be44a1e2f1ba255701c64ec20c80f172327309a9e70cc5af8c1cb7625000000000000000000017404000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1a014830450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf4401483045022100fabbd98f6b07631999104233c2c9191d6caa571d8dcce1bb22226f7b862449b1022055424cc3615fcb138237be5a13ac3a5fe306cb544eb39ab8953bcd4245575a9b01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 6,1
					index:           3,
					remoteSigHex:    "30440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d",
					resolutionTxHex: "0200000001e40a648be44a1e2f1ba255701c64ec20c80f172327309a9e70cc5af8c1cb7625010000000000000000015c08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd19014730440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d01483045022100a844b76869fb53809e44ad9607646d706bf8d9d0bff2e4574a8754330b5e1ea4022063c5824e8ccd4d9c514dc34c7e556364a08d572ed3ebfe77141951ed38e11c5401004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 6,2
					index:           4,
					remoteSigHex:    "3045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a",
					resolutionTxHex: "02000000000101fb824d4e4dafc0f567789dee3a6bce8d411fe80f5563d8cdfdcc7d7e4447d43a020000000000000000019a090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a01483045022100ff200bc934ab26ce9a559e998ceb0aee53bc40368e114ab9d3054d9960546e2802202496856ca163ac12c143110b6b3ac9d598df7254f2e17b3b94c3ab5301f4c3b0012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8005d007000000000000000017a914caedc83de8579ddc703de39b99b47fcb806f2e6987b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ace29c6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd947304402204ac0dd323a567e0bf7d5f96da34906e7c7fc78d9871fe4e47670e1ad6642960f02200e423422d47857d45b337b063b01b2f76262a16a18c4b127667570fcf5236c0e0148304502210092f595d716992a45f81394ff08ebfb8b8f97f299801b7087854bdb25429901e802200ec3c6ff71bf250f7c75cff228cf9bef0bc77bfb06c4cb4cefb32332beca85fb01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304502210092f595d716992a45f81394ff08ebfb8b8f97f299801b7087854bdb25429901e802200ec3c6ff71bf250f7c75cff228cf9bef0bc77bfb06c4cb4cefb32332beca85fb",
		},
		{ // 7
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      2195,
			},
			htlcDescs: []htlcDesc{
				{ // 7,0
					index:           3,
					remoteSigHex:    "3045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc",
					resolutionTxHex: "02000000011adc2d15b55db8051b3e59f20c90c20bed00fa4d40894c3e28a28291f7e9bfea000000000000000000015c08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc01483045022100998a92958fb7c4442fbd502e87e670c3d91372c92efa97985f0589207f1d3f530220623810042dfb0492074825f0e973ab17fd64112eab1151213153c5e7bad0906501004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 7,1
					index:           4,
					remoteSigHex:    "3045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92",
					resolutionTxHex: "020000000001014e16c488fa158431c1a82e8f661240ec0a71ba0ce92f2721a6538c510226ad5c0100000000000000000199090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92014730440220665b9cb4a978c09d1ca8977a534999bc8a49da624d0c5439451dd69cde1a003d022070eae0620f01f3c1bd029cc1488da13fb40fdab76f396ccd335479a11c5276d8012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8004b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac2c9d6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100886b3aba60c005adeac1c282636a3d8a2a87d75186085eaefe33f064f9048b2102201503322c1974fef4f9347d1a9fb57097858992f53a7ac17f1586ce14c91e59e8014830450221008232d60cadc79e5b7ad5733c6f3528a0448f55c5086f00b07b74bfc3bb9b26fb02201ac5bc9c4b64ce4fd4be977e7622ff343c455475a86623de957869c2345f571801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30450221008232d60cadc79e5b7ad5733c6f3528a0448f55c5086f00b07b74bfc3bb9b26fb02201ac5bc9c4b64ce4fd4be977e7622ff343c455475a86623de957869c2345f5718",
		},
		{ // 8
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      3702,
			},
			htlcDescs: []htlcDesc{
				{ // 8,0
					index:           3,
					remoteSigHex:    "3045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb",
					resolutionTxHex: "020000000137951077ec6b82f990ff3453df44a6025e5fb25bc145c0db79098f3d2c0b6b7f000000000000000000010d06000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901483045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb01473044022037497a5a19941e0a28b319f4a336f10c65bf9ac0a8788fc5c163b842b066ec30022051c42baacbdd5c0bad1cf116faa11b1b31d48bf03c5f9a80f299d0f9782d7e2d01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 8,1
					index:           4,
					remoteSigHex:    "3045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9",
					resolutionTxHex: "02000000000101b8de11eb51c22498fe39722c7227b6e55ff1a94146cf638458cb9bc6a060d3a30100000000000000000176050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9014730440220048a41c660c4841693de037d00a407810389f4574b3286afb7bc392a438fa3f802200401d71fa87c64fe621b49ac07e3bf85157ac680acb977124da28652cc7f1a5c012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8004b80b000000000000000017a91458c79bd690486ff9f77788fbcf31ee9c3c799c2387a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88aca19a6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd8473044022000dbf0e0858cd19ee475ae0022f1eab476cae4a07e51deaed899f9544d1438a4022021c9f75beb1d99b9f171b4008920de9d445ead787fa74956bc68842a59fc99370147304402202e527d7239610e3e0cfecaa0e9e1e7cefbc8d53a2a5ff176edad29a638d35d3a022078500d672b7d1667b2b7d591b6f4a87500f8dda35d88440dabcfb8b03dd01d2e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402202e527d7239610e3e0cfecaa0e9e1e7cefbc8d53a2a5ff176edad29a638d35d3a022078500d672b7d1667b2b7d591b6f4a87500f8dda35d88440dabcfb8b03dd01d2e",
		},
		{ // 9
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      3703,
			},
			htlcDescs: []htlcDesc{
				{ // 9,0
					index:           4,
					remoteSigHex:    "3044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd",
					resolutionTxHex: "020000000001011c076aa7fb3d7460d10df69432c904227ea84bbf3134d4ceee5fb0f135ef206d0000000000000000000175050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd01483045022100b94d931a811b32eeb885c28ddcf999ae1981893b21dd1329929543fe87ce793002206370107fdd151c5f2384f9ceb71b3107c69c74c8ed5a28a94a4ab2d27d3b0724012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8003a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac1f9b6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100a13d9022670798075ceb448c8980308740944ebec10ea3ebbd6f60b5065058710220275e3c315db31702557be4d8a5e9ab6989f41a477f17c070af91fd2f7eed659d01483045022100828292959e5bcd5a4f612ea6474a15969c28f66991ced5498bc55cc053984ec90220210798ed0e2e3055ffb5f732487283ff4ce275426b7868d88e04a800a7184a5101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100828292959e5bcd5a4f612ea6474a15969c28f66991ced5498bc55cc053984ec90220210798ed0e2e3055ffb5f732487283ff4ce275426b7868d88e04a800a7184a51",
		},
		{ // 10
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      4914,
			},
			htlcDescs: []htlcDesc{
				{ // 10,0
					index:           4,
					remoteSigHex:    "3045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf",
					resolutionTxHex: "0200000000010110a3fdcbcd5db477cd3ad465e7f501ffa8c437e8301f00a6061138590add757f0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf0148304502210086e76b460ddd3cea10525fba298405d3fe11383e56966a5091811368362f689a02200f72ee75657915e0ede89c28709acd113ede9e1b7be520e3bc5cda425ecd6e68012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8003a00f000000000000000017a914dbc3669fefd825bb93c350b649c744dcaa676e4a87c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac3d996a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9483045022100c9c5dc4445cab4b263528275821f4971b740e56252e5dc93b5c086727610fb850220273a39ebc1c63b426819cf35c1afae1a247f4561bde4b873132462d8a24c3f1401473044022006b967d091c6f975810eea2d32fc0bbd4cd70552e220180297ab7c0f3263550802205af3a0636fd8776e81521a42cf6e2e38f1f1d61ad428a788f9e7acca9878328101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3044022006b967d091c6f975810eea2d32fc0bbd4cd70552e220180297ab7c0f3263550802205af3a0636fd8776e81521a42cf6e2e38f1f1d61ad428a788f9e7acca98783281",
		},
		{ // 11
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      4915,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ace3996a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd847304402204944fc6c6aa2596bc03cad1eb5a5eea45adbfd75e77821a5b3ababbfab18ba240220419a998606deddd172e861f48963dad9869ef550c1d52dc0cbc00438c53f876401473044022100eadee4de1c138726ce6d9059df778c2e29129a6da82501c24bfaf1a395b8e7f4021f7dec49f15a031b548dce9329100e7233d57d2f88ac2dfdfac6de058228a7bb01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3044022100eadee4de1c138726ce6d9059df778c2e29129a6da82501c24bfaf1a395b8e7f4021f7dec49f15a031b548dce9329100e7233d57d2f88ac2dfdfac6de058228a7bb",
		},
		{ // 12
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      9651180,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac1b06350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9483045022100a8f9830db0e70d129c6b788559c67e3be08bd9640d1ec842ff5de33f13e3a0fa02203722ce335cd06dfba949dd794f368df614ed33603ce8a9f5cb274023a7802ed70147304402203a8e0846da89ea077bce25a95fb3122b43b4f6414a2d93eefc3dab3c4470f4c302202405cd483e82c1e9782a5c8305c1d2d1735d47e0acd3833b4caf20e7c323341d01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402203a8e0846da89ea077bce25a95fb3122b43b4f6414a2d93eefc3dab3c4470f4c302202405cd483e82c1e9782a5c8305c1d2d1735d47e0acd3833b4caf20e7c323341d",
		},
		{ // 13
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      9651181,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac1b06350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9483045022100a8f9830db0e70d129c6b788559c67e3be08bd9640d1ec842ff5de33f13e3a0fa02203722ce335cd06dfba949dd794f368df614ed33603ce8a9f5cb274023a7802ed70147304402203a8e0846da89ea077bce25a95fb3122b43b4f6414a2d93eefc3dab3c4470f4c302202405cd483e82c1e9782a5c8305c1d2d1735d47e0acd3833b4caf20e7c323341d01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402203a8e0846da89ea077bce25a95fb3122b43b4f6414a2d93eefc3dab3c4470f4c302202405cd483e82c1e9782a5c8305c1d2d1735d47e0acd3833b4caf20e7c323341d",
		},
		{ // 14
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKw:      9651936,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a91476af2ec453973bb9c6c22350d46683553fe5bb4b88ac0805350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd847304402207ee47f429d3d2716d0c45c30396a6e7ace845fbbee1008560e3c190c3e29661302205445747af87429e1f5822dd35388ecff48cee12e5cae31e043b38ec515cd92380147304402200449747bd264ce1ad5b9f7570228996c5c4e7f46619fedb830669fe5f677fbfe02201406ff873d1818bb798c4cd392645f6e5f099a7591b475fcee45347cac62666301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402200449747bd264ce1ad5b9f7570228996c5c4e7f46619fedb830669fe5f677fbfe02201406ff873d1818bb798c4cd392645f6e5f099a7591b475fcee45347cac626663",
		},
	}

	pCache := &mockPreimageCache{
		// hash -> preimage
		preimageMap: make(map[[32]byte][]byte),
	}

	fundingTxOut := channel.signDesc.Output

	for i, test := range testCases {
		expectedCommitmentTx, err := txFromHex(test.expectedCommitmentTxHex)
		if err != nil {
			t.Fatalf("Case %d: Failed to parse serialized tx: %v", i, err)
		}

		// Build required HTLC structs from raw test vector data.
		htlcs := make([]channeldb.HTLC, len(test.htlcDescs), len(test.htlcDescs))
		for i, htlcDesc := range test.htlcDescs {
			htlcs[i], err = tc.getHTLC(i, &htlcDesc)
			if err != nil {
				t.Fatal(err)
			}
		}
		theHTLCView := htlcViewFromHTLCs(htlcs)

		// Create unsigned commitment transaction.
		commitmentView := &commitment{
			height:       test.commitment.CommitHeight,
			ourBalance:   test.commitment.LocalBalance,
			theirBalance: test.commitment.RemoteBalance,
			feePerKw:     AtomPerKByte(test.commitment.FeePerKw),
			dustLimit:    tc.dustLimit,
			isOurs:       true,
		}
		err = channel.createCommitmentTx(
			commitmentView, theHTLCView, keys,
		)
		if err != nil {
			t.Errorf("Case %d: Failed to create new commitment tx: %v", i, err)
			continue
		}

		// Initialize LocalCommit, which is used in getSignedCommitTx.
		channelState.LocalCommitment = test.commitment
		channelState.LocalCommitment.Htlcs = htlcs
		channelState.LocalCommitment.CommitTx = commitmentView.txn

		// This is the remote party's signature over the commitment
		// transaction which is included in the commitment tx's witness
		// data.
		channelState.LocalCommitment.CommitSig, err = hex.DecodeString(test.remoteSigHex)
		if err != nil {
			t.Fatalf("Case %d: Failed to parse serialized signature: %v",
				i, err)
		}

		commitTx, err := channel.getSignedCommitTx()
		if err != nil {
			t.Errorf("Case %d: Failed to sign commitment tx: %v", i, err)
			continue
		}

		// Sanity check the commitment to ensure it has a chance of being valid.
		if err = checkSignedCommitmentTxSanity(commitTx, fundingTxOut, tc.netParams) ; err != nil {
			t.Errorf("Case %d: Failed commitment tx sanity check: %v", i, err)
		}

		// Check that commitment transaction was created correctly.
		if commitTx.TxHashWitness() != expectedCommitmentTx.MsgTx().TxHashWitness() {
			t.Errorf("Case %d: Generated unexpected commitment tx: "+
				"expected %s, got %s", i, spew.Sdump(expectedCommitmentTx),
				 spew.Sdump(commitTx))

			continue
		}

		// Generate second-level HTLC transactions for HTLCs in
		// commitment tx.
		htlcResolutions, err := extractHtlcResolutions(
			AtomPerKByte(test.commitment.FeePerKw), true, signer,
			htlcs, keys, channel.localChanCfg, channel.remoteChanCfg,
			commitTx.TxHash(), pCache,
		)
		if err != nil {
			t.Errorf("Case %d: Failed to extract HTLC resolutions: %v", i, err)
			continue
		}

		resolutionIdx := 0
		for j, htlcDesc := range test.htlcDescs {
			// TODO: Check HTLC success transactions; currently not implemented.
			// resolutionIdx can be replaced by j when this is handled.
			if htlcs[j].Incoming {
				continue
			}

			expectedTx, err := txFromHex(htlcDesc.resolutionTxHex)
			if err != nil {
				t.Fatalf("Failed to parse serialized tx: %d %d %v", i, j, err)
			}

			htlcResolution := htlcResolutions.OutgoingHTLCs[resolutionIdx]
			resolutionIdx++

			actualTx := htlcResolution.SignedTimeoutTx
			if actualTx == nil {
				t.Errorf("Case %d: Failed to generate second level tx: "+
					"output %d, %v", i, j,
					htlcResolutions.OutgoingHTLCs[j])
				continue
			}

			// TODO(decred) Uncomment after working out correct test vectors.
			// Sanity check the resulting tx to ensure it has a chance of being
			// mined.
			// if err = checkSignedCommitmentSpendingTxSanity(actualTx, commitTx, tc.netParams) ; err != nil {
			// 	t.Errorf("Case %d: Failed htlc resolution tx sanity check: "+
			// 		"output %d, %v", i, j, err)
			// 	t.Fatalf("blergh")
			// }

			// Check that second-level HTLC transaction was created correctly.
			if actualTx.TxHashWitness() != expectedTx.MsgTx().TxHashWitness() {
				t.Errorf("Case %d: Generated unexpected second level tx: "+
					"output %d, expected %s, got %s", i, j,
					expectedTx.MsgTx().TxHashWitness(), actualTx.TxHashWitness())
				continue
			}
		}
	}
}

// htlcViewFromHTLCs constructs an htlcView of PaymentDescriptors from a slice
// of channeldb.HTLC structs.
func htlcViewFromHTLCs(htlcs []channeldb.HTLC) *htlcView {
	var theHTLCView htlcView
	for _, htlc := range htlcs {
		paymentDesc := &PaymentDescriptor{
			RHash:   htlc.RHash,
			Timeout: htlc.RefundTimeout,
			Amount:  htlc.Amt,
		}
		if htlc.Incoming {
			theHTLCView.theirUpdates =
				append(theHTLCView.theirUpdates, paymentDesc)
		} else {
			theHTLCView.ourUpdates =
				append(theHTLCView.ourUpdates, paymentDesc)
		}
	}
	return &theHTLCView
}
