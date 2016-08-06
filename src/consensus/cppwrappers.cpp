// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cppwrappers.h"

#include "chain.h"
#include "consensus.h"
#include "pow.h"

static const CoreIndexInterface coreIndexInterface;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& consensusParams)
{
    return PowGetNextWorkRequired(pindexLast, coreIndexInterface, pblock, consensusParams);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& consensusParams)
{
    return PowCalculateNextWorkRequired(pindexLast, coreIndexInterface, nFirstBlockTime, consensusParams);
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    return Consensus::ContextualCheckHeader(block, state, consensusParams, pindexPrev, coreIndexInterface, nAdjustedTime);
}
