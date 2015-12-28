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
class CBlockIndex;
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
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * If successful, It also adds the tx fees to nFees.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int64_t nSpendHeight, CAmount& nFees);
/**
 * Check whether that all scripts (and signatures) of the inputs of this transaction are valid.
 * This does not modify the UTXO set.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputsScripts(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheStore);
/**
 * Storage-dependent checks for a tx that is not a coinbase.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckNonCoinbaseTxStorage(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int64_t nSpendHeight, unsigned int flags, bool fScriptChecks, bool cacheStore, CAmount& nFees, int64_t& nSigOps);
/**
 * Fully verify a coinbase transaction.
 * Preconditions: tx.IsCoinBase() is true.
 */
bool VerifyCoinbaseTx(const CTransaction& tx, CValidationState& state, const int64_t nHeight, unsigned flags, int64_t& nSigOps);
/**
 * Fully verify a CTransaction.
 * @TODO this is incomplete, among other things, CheckTx() is not called from here yet.
 */
bool VerifyTx(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const int64_t nHeight, const int64_t nSpendHeight, const int64_t nLockTimeCutoff, unsigned int flags, bool fScriptChecks, bool cacheStore, CAmount& nFees, int64_t& nSigOps);

/** Block Header validation functions */

/**
 * Context-independent CBlockHeader validity checks
 */
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, bool fCheckPOW = true);
/**
 * Context-dependent CBlock validity checks
 */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, const CBlockIndex* pindexPrev);

/** Block validation functions */

/**
 * Context-independent CBlock validity checks
 */
bool CheckBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, int64_t nTime, bool fCheckPOW = true, bool fCheckMerkleRoot = true);
/**
 * @TODO Remove function see Consensus::VerifyTx().
 */
bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, const CBlockIndex* pindexPrev);

} // namespace Consensus

/** Transaction validation utility functions */

/**
 * @return the consensus LockTime cutoff (block.nTime before BIP113, pindexPrev->GetMedianTimePast() after).
 */
int64_t GetLockTimeCutoff(const CBlockHeader& block, const CBlockIndex* pindexPrev, const unsigned int flags);
/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime);
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

/**
 * Get the consensus flags to be enforced according to the block.nVersion history. 
 */
unsigned int GetConsensusFlags(const CBlockHeader& block, const Consensus::Params& consensusParams, const CBlockIndex* pindex);
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
