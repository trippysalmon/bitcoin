// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VERSIONBITS_H
#define BITCOIN_CONSENSUS_VERSIONBITS_H

#include "params.h"

class CBlockIndexView;
class CValidationState;

/**
 * Thee version bit reserved for signaling hardfork activation to all types of nodes (previously "sign bit").
 * See https://github.com/bitcoin/bips/pull/317 (TODO wait for BIP number)
 */
static const uint32_t HARDFORK_BIT = 1 << 31; // 1000...0
static const uint32_t UNUSED_RESERVED_BIT = UNUSED_RESERVED_BIT >> 1; // 0100...0
static const uint32_t VERSIONBIT_BIT = VERSIONBIT_BIT >> 1; // 0010...0
static const uint32_t RESERVED_BITS_MASK = HARDFORK_BIT | UNUSED_RESERVED_BIT | VERSIONBIT_BIT ; // 1110...0

/**
 * Implementation of BIP9, see https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
 */
namespace Consensus {

bool AppendVersionBitsFlags(unsigned int& flags, CValidationState& state, const Params& consensusParams, const CBlockIndexView* pIndexPrev, int64_t nMedianTime);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_VERSIONBITS_H
