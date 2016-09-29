// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gserver.h"

const std::string strMessageMagic = "Bitcoin Signed Message:\n";
bool fImporting = false;
bool fReindex = false;
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;

// Miner specific things follow:
uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint64_t nLastBlockWeight = 0;

int nScriptCheckThreads = 0;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
