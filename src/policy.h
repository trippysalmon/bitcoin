// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include "script/standard.h"

#include <map>
#include <string>

class CCoinsViewEfficient;
class CFeeRate;
class CTransaction;
class CTxOut;
class CValidationState;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Maximum number of signature check operations in an Standard P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;

extern CFeeRate minRelayTxFee;

/** Abstract interface for Policy */
class CPolicy
{
public:
    virtual void InitFromArgs(const std::map<std::string, std::string>&) = 0;
    virtual bool ValidateScript(const CScript&, txnouttype&) const = 0;
    virtual bool ValidateOutput(const CTxOut& txout) const = 0;
    /** Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
    virtual bool ValidateTx(const CTransaction&, CValidationState&) const = 0;
    /** 
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
    virtual bool ValidateTxInputs(const CTransaction&, const CCoinsViewEfficient&) const = 0;
};

/** Return a CPolicy of the type described in the parameter string */
CPolicy& Policy(std::string);
/** Returns the current CPolicy. Requires calling SelectPolicy() or InitPolicyFromArgs() first */
const CPolicy& Policy();
/** Selects the current CPolicy of the type described in the parameter string */
void SelectPolicy(std::string);
/** Returns a HelpMessage string with policy options */
std::string GetPolicyUsageStr();
/** 
 * Selects the current CPolicy of the type described in the string on key "-policy" mapArgs
 * and calls CPolicy::InitFromArgs() with mapArgs.
 */
void InitPolicyFromArgs(const std::map<std::string, std::string>& mapArgs);

#endif // BITCOIN_POLICY_H
