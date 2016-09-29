// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GLOBALS_GSERVER_H
#define BITCOIN_GLOBALS_GSERVER_H

#include <string>

#include "amount.h"

extern const std::string strMessageMagic;
extern bool fImporting;
extern bool fReindex;
extern bool fTxIndex;
/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned;
/** True if we're running in -prune mode. */
extern bool fPruneMode;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern uint64_t nLastBlockWeight;
extern int nScriptCheckThreads;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern size_t nCoinCacheUsage;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;

#endif // BITCOIN_GLOBALS_GSERVER_H
