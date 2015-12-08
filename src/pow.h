// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include "consensus/params.h"
#include "consensus/structs.h"

#include <stdint.h>

class CBlockHeader;
class uint256;
class arith_uint256;

int64_t GetMedianTimePast(const CBaseBlockIndex* pindex, const Consensus::Params& consensusParams, PrevIndexGetter);

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
static inline int InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
inline int GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

/**
 * Efficiently find an ancestor of this block.
 */
CBaseBlockIndex* GetAncestor(const CBaseBlockIndex* pindex, int height, PrevIndexGetter, SkipIndexGetter);

unsigned int GetNextWorkRequired(const CBaseBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, PrevIndexGetter);
unsigned int CalculateNextWorkRequired(const CBaseBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // BITCOIN_POW_H
