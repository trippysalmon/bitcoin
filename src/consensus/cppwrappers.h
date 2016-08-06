// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CPPWRAPPERS_H
#define BITCOIN_CONSENSUS_CPPWRAPPERS_H

#include "params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class CValidationState;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& consensusParams);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& consensusParams);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, int64_t nAdjustedTime);

#endif // BITCOIN_CONSENSUS_CPPWRAPPERS_H
