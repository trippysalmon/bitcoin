// Copyright (c) 2015 Eric Lombrozo
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SOFTFORKS_H
#define BITCOIN_SOFTFORKS_H

#include <cstddef>

class CBlockIndex;
namespace Consensus {

struct Params;
namespace VersionBits { class BlockRuleIndex; }

namespace SoftForks {

enum VersionStatus { VALID, UNRECOGNIZED, INVALID };

VersionStatus CheckVersion(const CBlockIndex& blockIndex, const Consensus::VersionBits::BlockRuleIndex& blockRuleIndex, const Consensus::Params& consensusParams, CBlockIndex* pindexPrev = NULL);
bool UseRule(int rule, const CBlockIndex& blockIndex, const Consensus::VersionBits::State& versionBitsState, const Consensus::Params& consensusParams);
const char* GetRuleName(int rule);

} // namespace SoftForks
} // namespace Consensus

#endif // BITCOIN_SOFTFORKS_H
