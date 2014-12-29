// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include <string>

class CFeeRate;
class CTransaction;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;

extern bool fIsBareMultisigStd;
extern CFeeRate minRelayTxFee;

bool IsStandardTx(const CTransaction& tx, std::string& reason);
void InitPolicyFromCommandLine();

#endif // BITCOIN_POLICY_H
