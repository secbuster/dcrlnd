package keychain

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/hdkeychain"
	"github.com/decred/dcrwallet/errors"
	"github.com/decred/dcrwallet/wallet"
	"github.com/decred/dcrwallet/wallet/udb"
)

const (
	// CoinTypeBitcoin specifies the BIP44 coin type for Bitcoin key
	// derivation.
	CoinTypeBitcoin uint32 = 0

	// CoinTypeTestnet specifies the BIP44 coin type for all testnet key
	// derivation.
	CoinTypeTestnet = 1

	// CoinTypeLitecoin specifies the BIP44 coin type for Litecoin key
	// derivation.
	CoinTypeLitecoin = 2
)

var (
	// waddrmgrNamespaceKey is the namespace key that the waddrmgr state is
	// stored within the top-level waleltdb buckets of dcrwallet.
	waddrmgrNamespaceKey = []byte("waddrmgr")
)

// Yep I WalletKeyRing is an implementation of both the KeyRing and SecretKeyRing
// interfaces backed by dcrwallet's internal root udb.  Internally, we'll
// be using a ScopedKeyManager to do all of our derivations, using the key
// scope and scope addr scehma defined above. Re-using the existing key scope
// construction means that all key derivation will be protected under the root
// seed of the wallet, making each derived key fully deterministic.
type WalletKeyRing struct {
	// wallet is a pointer to the active instance of the dcrwallet core.
	// This is required as we'll need to manually open database
	// transactions in order to derive addresses and lookup relevant keys
	wallet *wallet.Wallet
}

// NewWalletKeyRing creates a new implementation of the
// keychain.SecretKeyRing interface backed by dcrwallet.
//
// NOTE: The passed udb.Manager MUST be unlocked in order for the keychain
// to function.
func NewWalletKeyRing(w *wallet.Wallet) SecretKeyRing {
	return &WalletKeyRing{
		wallet: w,
	}
}

// createAccountsUpTo creates all accounts representing key families up to (and
// including) the provided argument.
// TODO(decred) extremely inefficient for large keyFam. Ideally dcrwallet
// should support using arbitrary account numbers.
func (b *WalletKeyRing) createAccountsUpTo(keyFam KeyFamily) error {

	// If this is the multi-sig key family, then we can return early as
	// this is the default account that's created.
	if keyFam == KeyFamilyMultiSig {
		return nil
	}

	// Otherwise, we'll check if the account already exists, if so, we can
	// once again bail early.
	_, err := b.wallet.AccountName(uint32(keyFam))
	if err == nil {
		return nil
	}

	// Figure out all uncreated accounts between 0..keyFam
	accounts, err := b.wallet.Accounts()
	if err != nil {
		return nil
	}
	maxExistAccount := uint32(0)
	for _, acct := range accounts.Accounts {
		if acct.AccountNumber < uint32(keyFam) && acct.AccountNumber > maxExistAccount {
			maxExistAccount = acct.AccountNumber
		}
	}

	for i := uint32(maxExistAccount + 1); i < uint32(keyFam); i++ {
		_, err = b.wallet.NextAccount(fmt.Sprintf("%d", i))
		if err != nil {
			return err
		}
	}

	return nil
}

// keyDescriptorForAddress returns the key descriptor for the given wallet
// address. It assumes the address exists and is a P2PKH address, otherwise this
// will error.
func (b *WalletKeyRing) keyDescriptorForAddress(addr dcrutil.Address) (KeyDescriptor, error) {
	var emptyKeyDesc KeyDescriptor
	addrInfo, err := b.wallet.AddressInfo(addr)
	if err != nil {
		return emptyKeyDesc, err
	}

	pubAddrInfo, is := addrInfo.(udb.ManagedPubKeyAddress)
	if !is {
		return emptyKeyDesc, fmt.Errorf("Generated address is not a ManagedPubKeyAddress")
	}

	pubKey, is := pubAddrInfo.PubKey().(secp256k1.PublicKey)
	if !is {
		return emptyKeyDesc, fmt.Errorf("Generated address is not a secp256k1 address")
	}

	return KeyDescriptor{
		PubKey: &pubKey,
		KeyLocator: KeyLocator{
			Family: KeyFamily(pubAddrInfo.Account()),
			Index:  pubAddrInfo.Index(),
		},
	}, nil
}

// DeriveNextKey attempts to derive the *next* key within the key family
// (account in BIP43) specified. This method should return the next external
// child within this branch.
//
// NOTE: This is part of the keychain.KeyRing interface.
func (b *WalletKeyRing) DeriveNextKey(keyFam KeyFamily) (KeyDescriptor, error) {
	var (
		addr         dcrutil.Address
		err          error
		emptyKeyDesc KeyDescriptor
	)

	// TODO(decred) Confirm use of gapPolicyIgnore
	addr, err = b.wallet.NewExternalAddress(uint32(keyFam), wallet.WithGapPolicyIgnore())
	if err != nil && errors.Is(errors.NotExist, err) {
		// Account corresponding to this family does not exist. Create it.
		err = b.createAccountsUpTo(keyFam)
		if err != nil {
			return emptyKeyDesc, err
		}

		// And re-derive the next address for it.
		addr, err = b.wallet.NewExternalAddress(uint32(keyFam), wallet.WithGapPolicyIgnore())
		if err != nil {
			return emptyKeyDesc, err
		}
	}

	return b.keyDescriptorForAddress(addr)
}

// DeriveKey attempts to derive an arbitrary key specified by the passed
// KeyLocator. This may be used in several recovery scenarios, or when manually
// rotating something like our current default node key.
//
// NOTE: This is part of the keychain.KeyRing interface.
func (b *WalletKeyRing) DeriveKey(keyLoc KeyLocator) (KeyDescriptor, error) {
	var (
		emptyKeyDesc KeyDescriptor
		err          error
		addrs        []dcrutil.Address
	)

	err = b.createAccountsUpTo(keyLoc.Family)
	if err != nil {
		return emptyKeyDesc, err
	}

	// TODO(matheusd) This is abusing the AccountBranchAddressRange to return
	// an arbitrary address, given the wallet doesn't yet have a call for that.
	// Implement a correct call on the wallet.
	addrs, err = b.wallet.AccountBranchAddressRange(uint32(keyLoc.Family),
		udb.ExternalBranch, keyLoc.Index, keyLoc.Index+1)
	if err != nil {
		return emptyKeyDesc, err
	}
	if len(addrs) != 1 {
		panic("really, fix the call.")
	}

	return b.keyDescriptorForAddress(addrs[0])
}

// DerivePrivKey attempts to derive the private key that corresponds to the
// passed key descriptor.
//
// NOTE: This is part of the keychain.SecretKeyRing interface.
func (b *WalletKeyRing) DerivePrivKey(keyDesc KeyDescriptor) (*secp256k1.PrivateKey, error) {
	var (
		err                           error
		famMasterPub, branchMasterPub *hdkeychain.ExtendedKey
		addr                          dcrutil.Address
		wif                           string
	)

	// If the public key isn't set or they have a non-zero index,
	// then we know that the caller instead knows the derivation
	// path for a key.
	if keyDesc.PubKey == nil || keyDesc.Index > 0 {
		keyDesc, err = b.DeriveKey(keyDesc.KeyLocator)
		if err != nil {
			return nil, err
		}
	} else {
		// If the public key isn't nil, then this indicates that we
		// need to scan for the private key, assuming that we know the
		// valid key family.
		//
		// We'll grab the master pub key for the provided account (family) then
		// manually derive the addresses here.
		famMasterPub, err = b.wallet.MasterPubKey(uint32(keyDesc.Family))
		if err != nil {
			return nil, err
		}
		branchMasterPub, err = famMasterPub.Child(udb.ExternalBranch)
		if err != nil {
			return nil, err
		}

		// We'll now iterate through our key range in an attempt to
		// find the target public key.
		// TODO(roasbeef): possibly move scanning into wallet to allow
		// to be parallelized

		found := false
		for i := 0; i < MaxKeyRangeScan; i++ {
			// Derive the next key in the range and fetch its
			// managed address.
			hdAddr, err := branchMasterPub.Child(uint32(i))
			if err == hdkeychain.ErrInvalidChild {
				continue
			}

			if err != nil {
				return nil, err
			}

			pubKey, err := hdAddr.ECPubKey()
			if err != nil {
				// simply skip invalid keys here
				continue
			}

			if keyDesc.PubKey.IsEqual(pubKey) {
				// We found the index of the address. Advance the wallet
				// addresses for up to this index.
				// This is only needed because dcrwallet does not have an
				// api call to retrieve arbitrary private keys.
				err = b.wallet.ExtendWatchedAddresses(uint32(keyDesc.Family),
					udb.ExternalBranch, uint32(i))
				if err != nil {
					return nil, err
				}

				keyDesc.Index = uint32(i)
				found = true
				break
			}
		}

		if !found {
			return nil, ErrCannotDerivePrivKey
		}
	}

	// So at this point, the wallet should have recorded the address of the
	// given public key and we should have filled keyDesc.PubKey. Fetch the
	// corresponding private key
	//
	// TODO(decred) This is abusing the DumpWIF endpoint. Please implement a
	// proper PrivateKeyForAddress call.
	addr, err = dcrutil.NewAddressPubKeyHash(dcrutil.Hash160(keyDesc.PubKey.Serialize()),
		b.wallet.ChainParams(), dcrec.STEcdsaSecp256k1)
	if err != nil {
		return nil, err
	}
	wif, err = b.wallet.DumpWIFPrivateKey(addr)
	if err != nil {
		return nil, err
	}

	wifKey, err := dcrutil.DecodeWIF(wif)
	if err != nil {
		return nil, err
	}

	privKey := wifKey.PrivKey.(*secp256k1.PrivateKey)
	return privKey, nil
}

// ScalarMult performs a scalar multiplication (ECDH-like operation) between
// the target key descriptor and remote public key. The output returned will be
// the sha256 of the resulting shared point serialized in compressed format. If
// k is our private key, and P is the public key, we perform the following
// operation:
//
//  sx := k*P s := sha256(sx.SerializeCompressed())
//
// NOTE: This is part of the keychain.SecretKeyRing interface.
func (b *WalletKeyRing) ScalarMult(keyDesc KeyDescriptor,
	pub *secp256k1.PublicKey) ([]byte, error) {

	privKey, err := b.DerivePrivKey(keyDesc)
	if err != nil {
		return nil, err
	}

	s := &secp256k1.PublicKey{}
	x, y := secp256k1.S256().ScalarMult(pub.X, pub.Y, privKey.D.Bytes())
	s.X = x
	s.Y = y

	h := sha256.Sum256(s.SerializeCompressed())

	return h[:], nil
}
