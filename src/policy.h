// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_H
#define BITCOIN_POLICY_H

#include <string>

class CFeeRate;
class CTransaction;
class CCoinsViewCache;

/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;

extern bool fIsBareMultisigStd;
extern CFeeRate minRelayTxFee;

/** Abstract interface for Policy */
class CPolicy
{
public:
    virtual bool CheckTxPreInputs(const CTransaction& tx, std::string& reason) const = 0;
    virtual bool CheckTxWithInputs(const CTransaction& tx, const CCoinsViewCache& mapInputs) const = 0;
};

/** Standard Policy implementing CPolicy */
class CStandardPolicy : public CPolicy
{
public:
    virtual bool CheckTxPreInputs(const CTransaction& tx, std::string& reason) const;
    /**
     * Check transaction inputs to mitigate two
     * potential denial-of-service attacks:
     * 
     * 1. scriptSigs with extra data stuffed into them,
     *    not consumed by scriptPubKey (or P2SH script)
     * 2. P2SH scripts with a crazy number of expensive
     *    CHECKSIG/CHECKMULTISIG operations
     */
    virtual bool CheckTxWithInputs(const CTransaction& tx, const CCoinsViewCache& mapInputs) const;
};

const CPolicy& Policy();
void InitPolicyFromCommandLine();

#endif // BITCOIN_POLICY_H
