// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include "script/standard.h"

#include <string>

class CCoinsViewCache;
class CFeeRate;
class CTransaction;
class CTxOut;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Maximum number of signature check operations in an Standard P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
static const unsigned int MAX_OP_RETURN_RELAY = 40; //! bytes

extern CFeeRate minRelayTxFee;

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType);
bool IsDust(const CTxOut& txout);
/** Check for standard transaction types
 * @return True if all outputs (scriptPubKeys) use only standard transaction forms
 */
bool IsStandardTx(const CTransaction& tx, std::string& reason);
/** 
 * Check for standard transaction types
 * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
 * @return True if all inputs (scriptSigs) use only standard transaction forms
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);

void InitPolicyFromCommandLine();

#endif // BITCOIN_POLICY_H
