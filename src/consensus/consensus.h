// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

class CCoinsViewEfficient;
class CTransaction;
class CValidationState;

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 1000000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/** 
 * Consensus validations:
 * Check_ means checking everything possible with the data provided.
 * Verify_ means all data provided was enough for this level and its "consensus-verified".
 */
namespace Consensus {

bool CheckTx(const CTransaction& tx, CValidationState &state);

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewEfficient& inputs, int nSpendHeight);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
