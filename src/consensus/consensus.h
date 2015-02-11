// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "consensus/params.h"
#include "script/interpreter.h"

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CCoinsViewEfficient;
class CValidationState;

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. */
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC
/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 * 
 * Failing one of these tests may trigger a DoS ban - see Consensus::CheckTxInputsScripts() for
 * details.
 */
static const unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

/**
 * Consensus validations:
 * Check_ means checking everything possible with the data provided.
 * Verify_ means all data provided was enough for this level and its "consensus-verified".
 */
namespace Consensus {

/** Context-independent validity checks */
bool CheckTx(const CTransaction& tx, CValidationState &state);
bool CheckBlockHeader(const CBlockHeader& block, int64_t nTime, CValidationState& state, const Consensus::Params& params, bool fCheckPOW = true);
bool CheckBlock(const CBlock& block, int64_t nTime, CValidationState& state, const Consensus::Params& params, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Context-dependent validity checks */
/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewEfficient& inputs, int nSpendHeight);
/**
 * Preconditions: tx.IsCoinBase() is false.
 * Check whether all inputs of this transaction are valid (scripts and sigs)
 * This does not modify the UTXO set. This does not check double spends and amounts.
 * This is the more expensive consensus check for a transaction, do it last.
 */
bool CheckTxInputsScripts(const CTransaction& tx, CValidationState& state, const CCoinsViewEfficient& inputs, bool cacheStore, unsigned int flags=MANDATORY_SCRIPT_VERIFY_FLAGS);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex* pindexPrev, const Consensus::Params& params);

/** Utility functions */
/**
 * BIP16 didn't become active until Apr 1 2012
 * Starts enforcing the DERSIG (BIP66) rules, for block.nVersion=3 blocks, when 75% of the network has upgraded
 */
unsigned int GetFlags(const CBlock& block, CBlockIndex* pindex, const Consensus::Params& params);
/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);
/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewEfficient& mapInputs);
CAmount GetBlockValue(int nHeight, const Consensus::Params& params, const CAmount& nFees);

} // namespace Consensus

bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, unsigned nToCheck);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
