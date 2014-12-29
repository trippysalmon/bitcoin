// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include "amount.h"
#include "script/standard.h"

#include <map>
#include <string>

class CTransaction;
class CTxOut;
class CValidationState;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;

/** PolicyGlobal variables are supposed to become CStandardPolicy attributes */
namespace PolicyGlobal {

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
static CFeeRate minRelayTxFee = CFeeRate(1000);

} // namespace PolicyGlobal

/** Abstract interface for Policy */
class CPolicy
{
public:
    virtual void InitFromArgs(const std::map<std::string, std::string>&) = 0;
    virtual bool ValidateScript(const CScript&, txnouttype&) const = 0;
    virtual bool ValidateOutput(const CTxOut& txout) const = 0;
    virtual bool ValidateFee(const CAmount&, size_t) const = 0;
    /** Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
    virtual bool ValidateTx(const CTransaction&, CValidationState&) const = 0;
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
