// Copyright (c) 2015 Eric Lombrozo
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SOFTFORKS_H
#define BITCOIN_SOFTFORKS_H

#include <cstddef>

#include "consensus/params.h"

class CBlockHeader;
class CBlockIndex;
class CValidationState;

namespace Consensus {

namespace VersionBits
{
const int           VERSION_HIGH_BITS   = 0x20000000;
const int           VERSION_BITS_MASK   = 0x1fffffff;
const char          MIN_BIT             = 0;
const char          MAX_BIT             = 28;

enum RuleState { UNDEFINED, DEFINED, LOCKED_IN, ACTIVE, FAILED };

struct State
{
    RuleState vRuleStates[MAX_VERSION_BITS_DEPLOYMENTS];
};

bool CalculateState(State& newState, CValidationState& state, const Consensus::Params& consensusParams, const State& prevState, const CBlockIndex& blockIndex);
} // namespace VersionBits

bool CheckVersion(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex& blockIndex, const VersionBits::State& versionBitsState);
bool UseRule(int rule, const CBlockIndex& blockIndex, const Consensus::Params& consensusParams, const VersionBits::State& versionBitsState);

} // namespace Consensus

#endif // BITCOIN_SOFTFORKS_H
