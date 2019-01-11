package dcrwallet

import (
	"encoding/hex"
	"errors"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"

	"github.com/decred/dcrlnd/lnwallet"
)

var (
	// ErrOutputSpent is returned by the GetUtxo method if the target output
	// for lookup has already been spent.
	ErrOutputSpent = errors.New("target output has been spent")

	// ErrOutputNotFound signals that the desired output could not be
	// located.
	ErrOutputNotFound = errors.New("target output was not found")
)

// GetBestBlock returns the current height and hash of the best known block
// within the main chain.
//
// This method is a part of the lnwallet.BlockChainIO interface.
func (b *DcrWallet) GetBestBlock() (*chainhash.Hash, int32, error) {
	hash, height, err := b.chain.GetBestBlock()
	return hash, int32(height), err
}

// GetUtxo returns the original output referenced by the passed outpoint that
// create the target pkScript.
//
// This method is a part of the lnwallet.BlockChainIO interface.
func (b *DcrWallet) GetUtxo(op *wire.OutPoint, pkScript []byte,
	heightHint uint32) (*wire.TxOut, error) {

	txout, err := b.chain.GetTxOut(&op.Hash, op.Index, false)
	if err != nil {
		return nil, err
	} else if txout == nil {
		return nil, ErrOutputSpent
	}

	pkScript, err = hex.DecodeString(txout.ScriptPubKey.Hex)
	if err != nil {
		return nil, err
	}

	// Sadly, gettxout returns the output value in DCR instead of atoms.
	amt, err := dcrutil.NewAmount(txout.Value)
	if err != nil {
		return nil, err
	}

	return &wire.TxOut{
		Value:    int64(amt),
		PkScript: pkScript,
	}, nil
}

// GetBlock returns a raw block from the server given its hash.
//
// This method is a part of the lnwallet.BlockChainIO interface.
func (b *DcrWallet) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	return b.chain.GetBlock(blockHash)
}

// GetBlockHash returns the hash of the block in the best blockchain at the
// given height.
//
// This method is a part of the lnwallet.BlockChainIO interface.
func (b *DcrWallet) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	return b.chain.GetBlockHash(blockHeight)
}

// A compile time check to ensure that DcrWallet implements the BlockChainIO
// interface.
var _ lnwallet.WalletController = (*DcrWallet)(nil)
