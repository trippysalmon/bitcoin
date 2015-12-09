// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "primitives/block.h"
#include "uint256.h"

#include <algorithm>

int64_t GetMedianTimePast(const CBaseBlockIndex* pindex, const Consensus::Params& consensusParams, PrevIndexGetter indexGetter)
{
    int64_t pmedian[consensusParams.nPowMedianTimeSpan];
    int64_t* pbegin = &pmedian[consensusParams.nPowMedianTimeSpan];
    int64_t* pend = &pmedian[consensusParams.nPowMedianTimeSpan];

    for (unsigned int i = 0; i < consensusParams.nPowMedianTimeSpan && pindex; i++, pindex = indexGetter(pindex))
        *(--pbegin) = (int64_t)pindex->nTime;

    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin)/2];
}

static CBaseBlockIndex* GetAncestorStep(const CBaseBlockIndex* pindex, const int height, int& heightWalk, PrevIndexGetter indexGetter, SkipIndexGetter skipGetter)
{
    CBaseBlockIndex* pindexWalk;
    int heightSkip = GetSkipHeight(heightWalk);
    int heightSkipPrev = GetSkipHeight(heightWalk - 1);
    CBaseBlockIndex* pskip = skipGetter(pindex);
    if (pskip != NULL &&
        (heightSkip == height ||
         (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                   heightSkipPrev >= height)))) {
        // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
        pindexWalk = pskip;
        heightWalk = heightSkip;
    } else {
        pindexWalk = indexGetter(pindex);
        heightWalk--;
    }
    return pindexWalk;
}

CBaseBlockIndex* GetAncestor(const CBaseBlockIndex* pindex, int height, PrevIndexGetter indexGetter, SkipIndexGetter skipGetter)
{
    if (height > pindex->nHeight || height < 0)
        return NULL;

    int heightWalk = pindex->nHeight;
    CBaseBlockIndex* pindexWalk = GetAncestorStep(pindex, height, heightWalk, indexGetter, skipGetter);
    while (heightWalk > height)
        pindexWalk = GetAncestorStep(pindexWalk, height, heightWalk, indexGetter, skipGetter);

    return pindexWalk;
}

unsigned int GetNextWorkRequired(const CBaseBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, PrevIndexGetter indexGetter, SkipIndexGetter skipGetter)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->nTime + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBaseBlockIndex* pindex = pindexLast;
                while (indexGetter(pindex) && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = indexGetter(pindex);
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBaseBlockIndex* pindexFirst = GetAncestor(pindexLast, nHeightFirst, indexGetter, skipGetter);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->nTime, params);
}

unsigned int CalculateNextWorkRequired(const CBaseBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->nTime - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
