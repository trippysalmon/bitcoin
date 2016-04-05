// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GLOBALS_COMMON_H
#define BITCOIN_GLOBALS_COMMON_H

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
extern bool fLogTimestamps;
extern bool fLogTimeMicros;
extern bool fLogIPs;
extern volatile bool fReopenDebugLog;

extern const char* const BITCOIN_CONF_FILENAME;
extern const char* const BITCOIN_PID_FILENAME;

#endif // BITCOIN_GLOBALS_COMMON_H
