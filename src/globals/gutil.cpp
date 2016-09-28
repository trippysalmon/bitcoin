// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gutil.h"

#include "util.h"

const char * const BITCOIN_CONF_FILENAME = "bitcoin.conf";
const char * const BITCOIN_PID_FILENAME = "bitcoind.pid";

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

std::map<std::string, std::string> mapArgs;
std::map<std::string, std::vector<std::string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fServer = false;
std::string strMiscWarning;
bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
std::atomic<bool> fReopenDebugLog(false);
CTranslationInterface translationInterface;

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

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    return GetArg(strArg, strDefault, mapArgs);
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    return GetArg(strArg, nDefault, mapArgs);
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    return GetBoolArg(strArg, fDefault, mapArgs);
}
