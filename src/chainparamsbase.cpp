// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "util.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 8332;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseMainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 18332;
        strDataDir = "testnet3";
    }
};
static CBaseTestNetParams testNetParams;

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseTestNetParams
{
public:
    CBaseRegTestParams()
    {
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

/*
 * Unit test
 */
class CBaseUnitTestParams : public CBaseMainParams
{
public:
    CBaseUnitTestParams()
    {
        strDataDir = "unittest";
    }
};
static CBaseUnitTestParams unitTestParams;

static CBaseChainParams* pCurrentBaseParams = 0;

const CBaseChainParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

void SelectBaseParams(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        pCurrentBaseParams = &mainParams;
        break;
    case CBaseChainParams::TESTNET:
        pCurrentBaseParams = &testNetParams;
        break;
    case CBaseChainParams::REGTEST:
        pCurrentBaseParams = &regTestParams;
        break;
    case CBaseChainParams::UNITTEST:
        pCurrentBaseParams = &unitTestParams;
        break;
    default:
        throw std::runtime_error("Unimplemented network\n");
    }
}

CBaseChainParams::Network NetworkIdFromCommandLine()
{
    std::string network = GetArg("-network", "");
    if (network == "main")
        return CBaseChainParams::MAIN;
    if (network == "testnet")
        return CBaseChainParams::TESTNET;
    if (network == "testnet")
        return CBaseChainParams::REGTEST;
    if (network == "unittest")
        return CBaseChainParams::UNITTEST;
    if (network != "") {
        throw std::runtime_error("Unimplemented network " + network + "\n");
    }
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet. Additionally -testnet and -regtest are deprecated, use -network=testnet instead.\n");
    if (fRegTest) {
        LogPrintStr("WARNING: -regtest is deprecated, use -network=regtest instead.");
        return CBaseChainParams::REGTEST;
    }
    if (fTestNet) {
        LogPrintStr("WARNING: -testnet is deprecated, use -network=testnet instead.");
        return CBaseChainParams::TESTNET;
    }
    return CBaseChainParams::MAIN;
}

void SelectBaseParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    SelectBaseParams(network);
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
