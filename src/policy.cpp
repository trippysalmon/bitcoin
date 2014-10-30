// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "policy.h"

#include "amount.h"
#include "primitives/transaction.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
CFeeRate minRelayTxFee = CFeeRate(1000);

void InitPolicyFromCommandLine()
{
    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (mapArgs.count("-minrelaytxfee"))
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-minrelaytxfee"], n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            throw std::runtime_error(strprintf(_("Invalid amount for -minrelaytxfee=<amount>: '%s'"), mapArgs["-minrelaytxfee"]));
    }
}

bool IsDust(const CTxOut& txout)
{
    // "Dust" is defined in terms of CTransaction::minRelayTxFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more than 1/3 in fees
    // to spend something, then we consider it dust.
    // A typical txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a txout less than 546 satoshis 
    // with default minRelayTxFee.
    size_t nSize = txout.GetSerializeSize(SER_DISK,0) + 148u;
    return (txout.nValue < 3 * minRelayTxFee.GetFee(nSize));
}
