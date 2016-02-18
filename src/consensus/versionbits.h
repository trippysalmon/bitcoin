// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VERSIONBITS_H
#define BITCOIN_CONSENSUS_VERSIONBITS_H

#include "params.h"

class CBlockIndex;
class CValidationState;

/**
 * Implementation of BIP9, see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 */
namespace Consensus {

/** What block version to use for new blocks (pre versionbits) */
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/**
 * The version bit reserved for signaling hardfork activation to all types of nodes (previously "sign bit").
 * See https://github.com/bitcoin/bips/pull/317 (TODO wait for BIP number)
 */
static const uint32_t HARDFORK_BIT = 1 << 31; // 1000...0
static const uint32_t UNUSED_RESERVED_BIT = 1 << 30; // 0100...0
static const uint32_t VERSIONBIT_BIT = 1 << 29; // 0010...0
static const uint32_t RESERVED_BITS_MASK = HARDFORK_BIT | UNUSED_RESERVED_BIT | VERSIONBIT_BIT; // 1110...0

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Params& consensusParams);
/**
 * Get the consensus flags to be enforced according to the block.nVersion history. 
 */
unsigned int GetFlags(const CBlockIndex* pindexPrev, const Params& consensusParams, uint32_t& nOldestSfToNotify);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_VERSIONBITS_H
