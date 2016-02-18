// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"

#include "validation.h"
#include "storage_interfaces_cpp.h"
#include "script/interpreter.h"

using namespace Consensus;

/**
 * Initialize state of the deployments as DEFINED, perform some basic checks
 * and initialize the BIP9 states cache.
 * Can result in a consensus validation error if consensusParams contains deployments using incompatible bits.
 */
static bool InitVersionBitsState(CVersionBitsState& versionBitsState, CValidationState& state, const Params& consensusParams)
{
    versionBitsState.usedBitsMaskCache = RESERVED_BITS_MASK;
    for (int i = 0; i < MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const BIP9Deployment& deployment = consensusParams.vDeployments[i];

        if (deployment.bitmask & RESERVED_BITS_MASK)
            return state.DoS(100, false, REJECT_INVALID, "invalid-chainparams-incompatible-versionbits");
        versionBitsState.vStates[i] = DEFINED;
    }
    return true;
}

static bool MinersConfirmBitUpgrade(const BIP9Deployment& deployment, const Params& consensusParams, const CBlockIndexView* pIndexPrev)
{
    uint32_t nFound = 0;
    unsigned i = 0;
    while (i < consensusParams.nMinerConfirmationWindow && 
           nFound < consensusParams.nRuleChangeActivationThreshold && 
           pIndexPrev != NULL) {

        // If the versionbit bit (bit 29) is not set, the miner wasn't using BIP9 (as it mandates the high bits to be 001...)
        if (pIndexPrev->GetVersion() & deployment.bitmask && pIndexPrev->GetVersion() & VERSIONBIT_BIT)
            ++nFound;
        pIndexPrev = pIndexPrev->GetPrev();
        ++i;
    }
    return nFound >= consensusParams.nRuleChangeActivationThreshold;
}

/**
 * Calculate the next state from the previous one and the header chain.
 * Preconditions: 
 * - nextVersionBitsState = versionBitsState
 * - (indexPrev->GetHeight() + 1) % consensusParams.nMinerConfirmationWindow == 0
 */
static void CalculateNextState(const CVersionBitsState& versionBitsState, CVersionBitsState& nextVersionBitsState, const Params& consensusParams, const CBlockIndexView& indexPrev, int64_t nMedianTime)
{
    nextVersionBitsState = versionBitsState; // Copy the previous State
    for (int i = 0; i < MAX_VERSION_BITS_DEPLOYMENTS; ++i) {
        const BIP9Deployment& deployment = consensusParams.vDeployments[i];

        // ACTIVATED and FAILED states are final
        if (versionBitsState.vStates[i] == ACTIVATED || versionBitsState.vStates[i] == FAILED)
            break;

        if (versionBitsState.vStates[i] == DEFINED && 
            deployment.nStartTime < nMedianTime && 
            !(versionBitsState.usedBitsMaskCache & deployment.bitmask)) {

            nextVersionBitsState.usedBitsMaskCache |= deployment.bitmask;
            // If moved to STARTED it could potentially become LOCKED_IN or FAILED in the same round, so no need for break
            nextVersionBitsState.vStates[i] = STARTED;
        }

        // Check for Timeouts
        if (versionBitsState.vStates[i] == STARTED && deployment.nTimeout > nMedianTime) {
            nextVersionBitsState.vStates[i] = FAILED;
            break;
        }

        // If locked LOCKED_IN, advance to ACTIVATED and free the bit after
        // The order in which the BIPS are written in DeploymentPos (consensus/params.h) is potentially consensus critical
        // for this state: always leave older deployments at the beginning to reuse available bits immediately.
        if (versionBitsState.vStates[i] == LOCKED_IN) {
            // Don't use XOR to avoid thinking about an impossible case
            nextVersionBitsState.usedBitsMaskCache &= ~deployment.bitmask;
            nextVersionBitsState.vStates[i] = ACTIVATED;
            break;
        }

        if (versionBitsState.vStates[i] == STARTED && MinersConfirmBitUpgrade(deployment, consensusParams, &indexPrev)) {
            nextVersionBitsState.vStates[i] = LOCKED_IN;
            break;
        }
    }
}

/**
 * The key is the pointer of the CBlockIndex and the value, the corresponding Consensus::CVersionBitsState.
 */
class VersionBitsCache
{
public:
    std::map<const CBlockIndexView*, Consensus::CVersionBitsState> mVersionBitsCache;

    void Set(const CBlockIndexView* mapKey, const Consensus::CVersionBitsState& versionBitsState)
    {
        mVersionBitsCache[mapKey] = versionBitsState;
    }

    const Consensus::CVersionBitsState* Get(const CBlockIndexView* mapKey) const
    {
        const Consensus::CVersionBitsState* cachedState = NULL;
        if (mVersionBitsCache.count(mapKey))
            cachedState = &(mVersionBitsCache.at(mapKey));
        return cachedState;
    }
};

/**
 * This checks should never fail unless the states cache is exposed in the future.
 * No harm as long as the checks remain cheap.
 */
static bool PreconditionsPrevVersionBitsState(const CVersionBitsState& versionBitsState, CValidationState &state)
{
    // Make sure all reserved bits are active in versionBitsState.usedBitsMaskCache
    if (~versionBitsState.usedBitsMaskCache & RESERVED_BITS_MASK)
        return state.DoS(100, false, REJECT_INVALID, "invalid-BIP9-prevstate-incompatible-bits-not-reserved");

    for (int i = 0; i < MAX_VERSION_BITS_DEPLOYMENTS; ++i)
        if (versionBitsState.vStates[i] < DEFINED || versionBitsState.vStates[i] >= MAX_DEPLOYMENT_STATES)
            return state.DoS(100, false, REJECT_INVALID, "invalid-BIP9-prevstate-outofrange-state");

    return true;
}

/**
 * Get the last updated state for a given CBlockIndexView.
 */
const CVersionBitsState* GetVersionBitsState(const CBlockIndexView* pIndexPrev, CValidationState& state, const Params& consensusParams, int64_t nMedianTime)
{
    assert(pIndexPrev);

    // The height of the last ascendant with an updated CVersionBitsState is always 
    // a multiple of consensusParams.nMinerConfirmationWindow (see BIP9)
    const int64_t nPeriod = consensusParams.nMinerConfirmationWindow;
    const int64_t nTargetStateHeight = pIndexPrev->GetHeight() - ((pIndexPrev->GetHeight() + 1) % nPeriod);
    if (nTargetStateHeight != pIndexPrev->GetHeight())
        pIndexPrev = pIndexPrev->GetAncestorView(nTargetStateHeight);

    // Search backards for a cached state
    static VersionBitsCache versionBitsCache;
    const CBlockIndexView* itBlockIndex = pIndexPrev;
    const CVersionBitsState* pVersionBitsState = versionBitsCache.Get(itBlockIndex);
    while(!pVersionBitsState && itBlockIndex->GetHeight() > nPeriod) {
        // Only look in index with height % nPeriod == 0
        itBlockIndex = itBlockIndex->GetAncestorView(itBlockIndex->GetHeight() - nPeriod);
        pVersionBitsState = versionBitsCache.Get(itBlockIndex);
    }
    int64_t nCurrentStateHeight = itBlockIndex->GetHeight();

    // Create initial state if there's not one cached
    CVersionBitsState newVersionBitsState;
    if (pVersionBitsState) {
        if (!InitVersionBitsState(newVersionBitsState, state, consensusParams))
            return NULL;
        pVersionBitsState = &newVersionBitsState;
        nCurrentStateHeight = 0;
    }

    if (!PreconditionsPrevVersionBitsState(*pVersionBitsState, state))
        return NULL;

    // Calculate new states forward
    while (nCurrentStateHeight < nTargetStateHeight) {

        nCurrentStateHeight += nPeriod; // Move to the next Height that calculates a state
        itBlockIndex = pIndexPrev->GetAncestorView(nCurrentStateHeight);

        // Create the new state in the cache from the old one
        CalculateNextState(*pVersionBitsState, newVersionBitsState, consensusParams, *itBlockIndex, nMedianTime);
        versionBitsCache.Set(itBlockIndex, newVersionBitsState);
        pVersionBitsState = versionBitsCache.Get(itBlockIndex);
    }
    assert(nCurrentStateHeight == nTargetStateHeight);
    return pVersionBitsState;
}

bool AppendVersionBitsFlags(unsigned int& flags, CValidationState& state, const Params& consensusParams, const CBlockIndexView* pIndexPrev, int64_t nMedianTime)
{
    const CVersionBitsState* pVersionBitsState = GetVersionBitsState(pIndexPrev, state, consensusParams, nMedianTime);
    if (!pVersionBitsState)
        return false;

    if (pVersionBitsState->vStates[BIP113] == ACTIVATED)
        flags |= LOCKTIME_MEDIAN_TIME_PAST;

    return true;
}
