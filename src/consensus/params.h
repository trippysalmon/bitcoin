// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"

#define VERSIONBITS_UNIT_TEST

namespace Consensus {

enum Rule
{
#ifdef VERSIONBITS_UNIT_TEST
    TEST1,
    TEST2,
    TEST3,
    TEST4,
    TEST5,
    TEST6,
    TEST7,
    TEST8,
    TEST9,
    TEST10,
    TEST11,
    TEST12,
    TEST13,
    TEST14,
    TEST15,
    TEST16,
    TEST17,
    TEST18,
    TEST19,
    TEST20,
    TEST21,
    TEST22,
    TEST23,
    TEST24,
    TEST25,
    TEST26,
    TEST27,
    TEST28,
    TEST29,
    TEST30,
#endif
    MAX_VERSION_BITS_DEPLOYMENTS,
    // Old style deployments:
    BIP16,
    BIP30,
    BIP34,
    BIP65,
    BIP66,
    NO_RULE
};

struct SoftFork
{
    int32_t nBit;
    uint32_t nDeployTime;
    uint32_t nExpireTime;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Used for soft fork deployments using versionbits */
    int64_t nRuleChangeActivationThreshold;
    SoftFork vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
