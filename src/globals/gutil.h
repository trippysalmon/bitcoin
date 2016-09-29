// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GLOBALS_UTIL_H
#define BITCOIN_GLOBALS_UTIL_H

#include <atomic>
#include <map>
#include <string>
#include <vector>

extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;
extern bool fServer;
extern std::string strMiscWarning;
extern std::atomic<bool> fReopenDebugLog;

#endif // BITCOIN_GLOBALS_UTIL_H
