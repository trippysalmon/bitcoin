// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

unsigned int PowGetNextWorkRequired(const void* indexObject, const BlockIndexInterface& iBlockIndex, const CBlockHeader *pblock, const Consensus::Params& params)
{
    arith_uint256 arith_uint256_powLimit = UintToArith256(uint256A(params.pPowLimit));
    unsigned int nProofOfWorkLimit = arith_uint256_powLimit.GetCompact();

    // Genesis block
    if (indexObject == NULL)
        return nProofOfWorkLimit;

    int64_t difficultyAdjustmentInterval = params.nPowTargetTimespan / params.nPowTargetSpacing;
    // Only change once per difficulty adjustment interval
    if ((iBlockIndex.Height(indexObject)+1) % difficultyAdjustmentInterval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > iBlockIndex.Time(indexObject) + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const void* pindex = indexObject;
                while (iBlockIndex.Prev(pindex) &&
                       iBlockIndex.Height(pindex) % difficultyAdjustmentInterval != 0 && iBlockIndex.Bits(pindex) == nProofOfWorkLimit)
                    pindex = iBlockIndex.Prev(pindex);
                return iBlockIndex.Bits(pindex);
            }
        }
        return iBlockIndex.Bits(indexObject);
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = iBlockIndex.Height(indexObject) - (difficultyAdjustmentInterval-1);
    assert(nHeightFirst >= 0);
    const void* pindexFirst = iBlockIndex.Ancestor(indexObject, nHeightFirst);
    assert(pindexFirst);

    return PowCalculateNextWorkRequired(indexObject, iBlockIndex, iBlockIndex.Time(pindexFirst), params);
}

unsigned int PowCalculateNextWorkRequired(const void* indexObject, const BlockIndexInterface& iBlockIndex, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return iBlockIndex.Bits(indexObject);

    // Limit adjustment step
    int64_t nActualTimespan = iBlockIndex.Time(indexObject) - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(uint256A(params.pPowLimit));
    arith_uint256 bnNew;
    bnNew.SetCompact(iBlockIndex.Bits(indexObject));
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
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(uint256A(params.pPowLimit)))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
