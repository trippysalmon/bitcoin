// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_INTERFACE_H
#define BITCOIN_POLICY_INTERFACE_H

#include "amount.h"

#include <map>
#include <string>
#include <vector>

class CAutoFile;
class CCoinsViewCache;
class CFeeRate;
class CScript;
class CTransaction;
class CTxMemPoolEntry;
class CTxOut;
class CValidationState;
class uint256;

/**
 * \class CPolicy
 * Interface class for non-consensus-critical policy logic, like whether or not
 * a transaction should be relayed and/or included in blocks created.
 */
class CPolicy
{
public:
    virtual ~CPolicy() {};
    /**
     * @param argMap a map with options to read from.
     * @return a formatted HelpMessage string with the policy options
     */
    virtual std::vector<std::pair<std::string, std::string> > GetOptionsHelp() const = 0;
    /**
     * @param argMap a map with options to read from.
     * @return a formatted HelpMessage string with the policy options
     */
    virtual void InitFromArgs(const std::map<std::string, std::string>& argMap) = 0;
    /**
     * @param txout the CTxOut being considered
     * @return the minimum acceptable nValue for this CTxOut.
     */
    virtual CAmount GetDustThreshold(const CTxOut& txout) const = 0;
    virtual bool ApproveAbsurdFee(const CAmount& nFees, CValidationState& state, size_t nSize) const = 0;
    virtual bool ApproveFeeRate(const CFeeRate& nDeltaFeeRate) const = 0;
    virtual bool ApproveFreeTx(size_t nSize, CValidationState& state, const double& dNextBlockPriority, bool fIsPrioritized) const = 0;
    /**
     * @param txout the CTxOut being considered
     * @return True if the CTxOut has an acceptable nValue.
     */
    virtual bool ApproveOutputAmount(const CTxOut& txout) const = 0;
    virtual bool ApproveScript(const CScript& scriptPubKey) const = 0;
    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
    virtual bool ApproveTx(const CTransaction& tx, std::string& reason) const = 0;
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
    virtual bool ApproveTxInputs(const CTransaction& tx, const CCoinsViewCache& mapInputs) const = 0;
    /**
     *Process all the transactions that have been included in a block 
     */
    virtual void processBlock(unsigned int nBlockHeight, std::vector<CTxMemPoolEntry>& entries, bool fCurrentEstimate) = 0;
    /**
     * Process a transaction confirmed in a block
     */
    virtual void processBlockTx(unsigned int nBlockHeight, const CTxMemPoolEntry& entry) = 0;
    /**
     * Process a transaction accepted to the mempool
     */
    virtual void processTransaction(const CTxMemPoolEntry& entry, bool fCurrentEstimate) = 0;
    /**
     * Remove a transaction from the mempool tracking stats
     */
    virtual void removeTx(const uint256& hash) = 0;
    /**
     * Return a fee estimate 
     */
    virtual CFeeRate estimateFee(int confTarget) const = 0;
    /**
     * Return a priority estimate 
     */
    virtual double estimatePriority(int confTarget) const = 0;
    /**
     * Write estimation data to a file 
     */
    virtual void Write(CAutoFile& fileout) const = 0;
    /**
     * Read estimation data from a file 
     */
    virtual void Read(CAutoFile& filein) = 0;
};

namespace Policy {

/**
 * Append a help string for the options of the selected policy.
 * @param strUsage a formatted HelpMessage string with policy options
 * is appended to this string
 */
void AppendHelpMessages(std::string& strUsage);

/** Supported policies */
static const std::string STANDARD = "standard";

} // namespace Policy

#endif // BITCOIN_POLICY_INTERFACE_H
