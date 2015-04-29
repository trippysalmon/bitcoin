// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_FEES_H
#define BITCOIN_POLICY_FEES_H

#include "amount.h"

class CFeesPolicy
{
public:
    void seenBlock(const std::vector<CTxMemPoolEntry>& entries, int nBlockHeight, const CFeeRate minRelayFee) {}
    CFeeRate estimateFee(int nBlocksToConfirm) { return CFeeRate(0); }
    double estimatePriority(int nBlocksToConfirm) { return 0; }
    void Write(CAutoFile& fileout) const {}
    void Read(CAutoFile& filein, const CFeeRate& minRelayFee) {}
};

#endif // BITCOIN_POLICY_FEES_H
