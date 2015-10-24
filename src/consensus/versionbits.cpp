// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"

#include "consensus/params.h"
#include "tinyformat.h"

using namespace Consensus;
using namespace Consensus::VersionBits;

typedef std::multimap<int /*bit*/, int /*rule*/> RuleMap;
typedef std::map<int /*rule*/, const SoftFork*> SoftForkMap;

const char* Consensus::VersionBits::GetRuleStateText(int ruleState, bool bUseCaps)
{
    switch (ruleState)
    {
    case UNDEFINED:
        return bUseCaps ? "UNDEFINED" : "undefined";

    case DEFINED:
        return bUseCaps ? "DEFINED" : "defined";

    case LOCKED_IN:
        return bUseCaps ? "LOCKED IN" : "locked in";

    case ACTIVE:
        return bUseCaps ? "ACTIVE" : "active";

    case FAILED:
        return bUseCaps ? "FAILED" : "failed";

    default:
        return bUseCaps ? "N/A" : "n/a";
    }
}

bool Consensus::VersionBits::UsesVersionBits(int nVersion)
{
    return (nVersion & ~VERSION_BITS_MASK) == VERSION_HIGH_BITS;
}


SoftForkDeployments::~SoftForkDeployments()
{
    Clear();
}

void SoftForkDeployments::AddSoftFork(int rule, const Consensus::Params& consensusParams)
{
    const SoftFork& softfork = GetSoftFork(rule, consensusParams);
    if (softfork.nBit < MIN_BIT || softfork.nBit > MAX_BIT)
        throw std::runtime_error(strprintf("%s: invalid bit %d in rule %d", __func__, softfork.nBit, rule));

    if (softfork.nDeployTime >= softfork.nExpireTime)
        throw std::runtime_error(strprintf("%s: invalid time range in rule %d", __func__, rule));

    if (!IsBitAvailable(softfork.nBit, consensusParams, softfork.nDeployTime, softfork.nExpireTime))
        throw std::runtime_error(strprintf("%s: bit conflicts with existing softFork in rule %d", __func__, rule));

    m_rules.insert(std::pair<int, int>(softfork.nBit, rule));
}

bool SoftForkDeployments::IsBitAvailable(int bit, const Consensus::Params& consensusParams, uint32_t deployTime, uint32_t expireTime) const
{
    std::pair<RuleMap::const_iterator, RuleMap::const_iterator> range;
    range = m_rules.equal_range(bit);
    for (RuleMap::const_iterator rit = range.first; rit != range.second; ++rit)
    {
        // Do softFork times overlap?
        const SoftFork& softFork = GetSoftFork(rit->second, consensusParams);
        if (((deployTime >= softFork.nDeployTime) && (deployTime <  softFork.nExpireTime)) ||
            ((expireTime >  softFork.nDeployTime) && (expireTime <= softFork.nExpireTime)) ||
            ((deployTime <= softFork.nDeployTime) && (expireTime >= softFork.nExpireTime)))
                return false;
    }

    return true;
}

bool SoftForkDeployments::IsRuleAssigned(int rule, const Consensus::Params& consensusParams, uint32_t time) const
{
    const SoftFork& softFork = GetSoftFork(rule, consensusParams);
    return ((time >= softFork.nDeployTime) && (time < softFork.nExpireTime));
}

const SoftFork& SoftForkDeployments::GetSoftFork(int rule, const Consensus::Params& consensusParams) const
{
    if (rule >= MAX_VERSION_BITS_DEPLOYMENTS)
        throw std::runtime_error(strprintf("%s: rule %d not recognized.", __func__, rule));
    return consensusParams.vDeployments[rule];
}

const SoftFork& SoftForkDeployments::GetAssignedSoftFork(int bit, const Consensus::Params& consensusParams, uint32_t time) const
{
    std::pair<RuleMap::const_iterator, RuleMap::const_iterator> range;
    range = m_rules.equal_range(bit);
    for (RuleMap::const_iterator rit = range.first; rit != range.second; ++rit)
    {
        const SoftFork& softFork = GetSoftFork(rit->second, consensusParams);
        if ((time >= softFork.nDeployTime) && (time < softFork.nExpireTime))
            return softFork;
    }
    throw std::runtime_error(strprintf("%s: rule not assigned.", __func__));
}

int SoftForkDeployments::GetAssignedRule(int bit, const Consensus::Params& consensusParams, uint32_t time) const
{
    std::pair<RuleMap::const_iterator, RuleMap::const_iterator> range;
    range = m_rules.equal_range(bit);
    for (RuleMap::const_iterator rit = range.first; rit != range.second; ++rit) {
        int rule = rit->second;
        const SoftFork& softFork = GetSoftFork(rule, consensusParams);

        if ((time >= softFork.nDeployTime) && (time < softFork.nExpireTime))
            return rule;
    }

    return NO_RULE;
}

std::set<const SoftFork*> SoftForkDeployments::GetAssignedSoftForks(const Consensus::Params& consensusParams, uint32_t time) const
{
    std::set<const SoftFork*> softForks;
    for (RuleMap::const_iterator rit = m_rules.begin(); rit != m_rules.end(); ++rit) {
        const SoftFork& softFork = GetSoftFork(rit->second, consensusParams);
            softForks.insert(&softFork);
    }

    return softForks;
}

std::set<int> SoftForkDeployments::GetAssignedBits(const Consensus::Params& consensusParams, uint32_t time) const
{
    std::set<int> bits;
    for (RuleMap::const_iterator rit = m_rules.begin(); rit != m_rules.end(); ++rit) {
        const SoftFork& softFork = GetSoftFork(rit->second, consensusParams);
        if ((time >= softFork.nDeployTime) && (time < softFork.nExpireTime))
            bits.insert(softFork.nBit);
    }

    return bits;
}

std::set<int> SoftForkDeployments::GetAssignedRules(const Consensus::Params& consensusParams, uint32_t time) const
{
    std::set<int> rules;
    for (RuleMap::const_iterator rit = m_rules.begin(); rit != m_rules.end(); ++rit) {
        int rule = rit->second;
        const SoftFork& softFork = GetSoftFork(rule, consensusParams);
        if ((time >= softFork.nDeployTime) && (time < softFork.nExpireTime))
            rules.insert(rule);
    }

    return rules;
}

void SoftForkDeployments::Clear()
{
    m_rules.clear();
}
