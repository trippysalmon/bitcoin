// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gutil.h"

#include "util.h"

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams.get());
    return *globalChainBaseParams;
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams.reset(CBaseChainParams::Factory(chain));
}

bool AreBaseParamsConfigured()
{
    return globalChainBaseParams.get();
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    return GetArg(strArg, nDefault, mapArgs);
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    return GetBoolArg(strArg, fDefault, mapArgs);
}
