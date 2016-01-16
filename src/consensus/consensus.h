// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "amount.h"
#include "interfaces.h"
#include "params.h"

#include <stdint.h>

class CBlock;
class CBlockHeader;
class CBlockIndexView;
class CTransaction;
class CUtxoView;
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
 * @param in/out nFees: if successful, the tx fees are added to nFees.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const unsigned int flags, const CUtxoView& inputs, const int64_t nSpendHeight, CAmount& nFees, int64_t& nSigOps);

/**
 * Check whether that all scripts (and signatures) of the inputs of this transaction are valid.
 * This does not modify the UTXO set.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputsScripts(const CTransaction& tx, CValidationState& state, const CUtxoView& inputs, unsigned int flags, bool cacheStore);

/**
 * Checks specific to coinbase transactions.
 * Preconditions: tx.IsCoinBase() is true.
 */
bool CheckTxCoinbase(const CTransaction& tx, CValidationState& state, unsigned flags, const int64_t nHeight);

/**
 * Fully verify a CTransaction.
 *
 * @param in/out nFees: if successful, the tx fees are added to nFees.
 * @param in/out nSigOps: if successful, adds the total tx sigops to nSigOps. Otherwise it may have added the total, a part or nothing. 
 */
bool VerifyTx(const CTransaction& tx, CValidationState& state, const unsigned int flags, const int nHeight, const int64_t nMedianTimePast, const int64_t nBlockTime, bool fScriptChecks, bool cacheStore, const CBlockIndexView* pindexPrev, const CUtxoView& inputs, CAmount& nFees, int64_t& nSigOps);

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
/**
 * Fully verify a CBlockHeader.
 */
bool VerifyBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, const CBlockIndexView* pindexPrev, bool fCheckPOW=true);
/**
 *  Fully verify CBlockHeader. C-friendly interface
 */
bool VerifyBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, const void* pindexPrev, const BlockIndexInterface& indexInterface);

/** Block validation functions */

/**
 * Context-independent CBlock validity checks
 */
bool CheckBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, int64_t nTime, bool fCheckPOW = true, bool fCheckMerkleRoot = true);
/**
 * Fully verify a CBlock.
 */
bool VerifyBlock(const CBlock& block, CValidationState& state, const Params& consensusParams, int64_t nTime, const int64_t nSpendHeight, const CBlockIndexView* pindexPrev, const CUtxoView& inputs, bool fNewBlock, bool fScriptChecks, bool cacheStore, bool fCheckPOW, bool fCheckMerkleRoot);

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
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CUtxoView& mapInputs);
/**
 * Check whether all prevouts of the transaction are present in the UTXO set represented by this view.
 */
bool CheckTxHasInputs(const CTransaction& tx, const CUtxoView& inputs);

/** Block validation utility functions */

/**
 * Get the consensus flags to be enforced according to the block.nVersion history. 
 */
unsigned int GetConsensusFlags(const CBlockHeader& block, const Consensus::Params& consensusParams, const CBlockIndexView* pindex, bool fNewBlock);
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
