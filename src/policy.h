// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include "amount.h"
#include "script/standard.h"

#include <string>

class CBlockIndex;
class CBlockTemplate;
class CCoinsViewCache;
class CFeeRate;
class CTransaction;
class CTxMemPool;
class CTxMemPoolEntry;
class CTxOut;
class CValidationState;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Maximum number of signature check operations in an Standard P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
static const unsigned int MAX_OP_RETURN_RELAY = 40; //! bytes

extern CFeeRate minRelayTxFee;

/** Abstract interface for Policy */
class CPolicy
{
public:
    virtual bool CheckScript(const CScript& scriptPubKey, txnouttype& whichType) const = 0;
    virtual bool CheckOutput(const CTxOut& txout) const = 0;
    /** Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
    virtual bool CheckTxPreInputs(const CTransaction& tx, std::string& reason) const = 0;
    /** 
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
    virtual bool CheckTxWithInputs(const CTransaction& tx, const CCoinsViewCache& mapInputs) const = 0;
    virtual CAmount GetMinRelayFee(const CTransaction&, unsigned int nBytes, bool fAllowFree) const = 0;
    virtual bool AcceptTxPoolPreInputs(CTxMemPool&, CValidationState&, const CTransaction&) const = 0;
    virtual bool AcceptTxWithInputs(CTxMemPool&, CValidationState&, const CTransaction&, CCoinsViewCache&) const = 0;
    virtual bool AcceptMemPoolEntry(CTxMemPool&, CValidationState&, CTxMemPoolEntry&, CCoinsViewCache&, bool& fRateLimit) const = 0;
    virtual bool RateLimitTx(CTxMemPool&, CValidationState&, CTxMemPoolEntry&, CCoinsViewCache&) const = 0;
    /** Collect transactions (probably from the mempool) into a new block template
        @return Total amount of transaction fees collected by transactions
    */
    virtual bool BuildNewBlock(CBlockTemplate&, const CTxMemPool&, const CBlockIndex& indexPrev, CCoinsViewCache&) const = 0;
};

void SelectPolicy(std::string policyType);
CPolicy& Policy(std::string policyType);
const CPolicy& Policy();
void InitPolicyFromCommandLine();

#endif // BITCOIN_POLICY_H
