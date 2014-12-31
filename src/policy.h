// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

class CFeeRate;

extern CFeeRate minRelayTxFee;

void InitPolicyFromCommandLine();

#endif // BITCOIN_POLICY_H
