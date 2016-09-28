// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GLOBALS_UTIL_H
#define BITCOIN_GLOBALS_UTIL_H

#include "chainparamsbase.h"

#include <map>

extern std::map<std::string, std::string> mapArgs;

std::string GetArg(const std::string& strArg, const std::string& strDefault);
int64_t GetArg(const std::string& strArg, int64_t nDefault);
bool GetBoolArg(const std::string& strArg, bool fDefault);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseChainParams& BaseParams();

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string& chain);

/**
 * Return true if SelectBaseParamsFromCommandLine() has been called to select
 * a network.
 */
bool AreBaseParamsConfigured();

#endif // BITCOIN_GLOBALS_UTIL_H
