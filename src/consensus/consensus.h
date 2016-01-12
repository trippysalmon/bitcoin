// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "amount.h"
#include "consensus/params.h"

#include <stdint.h>

class CBlock;
class CBlockHeader;
class CBlockIndexView;
class CCoinsViewCache;
class CTransaction;
class CValidationState;

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/**
 * Context-independent CTransaction validity checks.
 * Nobody should spend an extra cycle on a transaction that doesn't pass this.
 */
bool CheckTransaction(const CTransaction& tx, CValidationState &state);

/**
 * Consensus validations (for Script, Tx, Header and Block):
 * Check_ means checking everything possible with the data provided.
 * Verify_ means all data provided was enough for this level and its "consensus-verified".
 */
namespace Consensus {

/** Transaction validation functions */

/**
 * Performs all tx the checks that are common for coinbase and regular transactions.
 * It doesn't require knowledge of the inputs (utxo).
 */
bool CheckTxPreInputs(const CTransaction& tx, CValidationState& state, const int nHeight, int64_t nLockTimeCutoff, int64_t& nSigOps);

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight);

/**
 * Fully verify a CTransaction.
 * @TODO this is incomplete, among other things, the scripts are not checked yet.
 */
bool VerifyTx(const CTransaction& tx, CValidationState& state, const unsigned int flags, const int nHeight, const int64_t nMedianTimePast, const int64_t nBlockTime, int64_t& nSigOps);

/** Block Header validation functions */

/**
 * Context-independent CBlockHeader validity checks
 */
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, bool fCheckPOW = true);
/**
 * Context-dependent CBlockHeader validity checks.
 * By "context", we mean only the previous block headers, but not the UTXO set.
 * UTXO-related validity checks are still done in main::ConnectBlock().
 */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, const CBlockIndexView* pindexPrev);

/** Block validation functions */

/**
 * Context-independent CBlock validity checks
 */
bool CheckBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, int64_t nTime, bool fCheckPOW = true, bool fCheckMerkleRoot = true);
/**
 * Context-dependent CBlock validity checks
 */
bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, const CBlockIndexView* pindexPrev);

} // namespace Consensus

/** Transaction validation utility functions */

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime);
/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndexView& block);
bool EvaluateSequenceLocks(const CBlockIndexView& block, std::pair<int, int64_t> lockPair);
/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndexView& block);

/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);
/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * 
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);

/** Block validation utility functions */

// TODO make static again
bool IsSuperMajority(int minVersion, const CBlockIndexView* pstart, unsigned nRequired, const Consensus::Params& consensusParams);
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
