// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "policy.h"

#include "amount.h"
#include "chainparams.h"
#include "coins.h"
#include "coinscache.h"
#include "consensus/validation.h"
#include "main.h"
#include "miner.h"
#include "primitives/transaction.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

static const std::string defaultMinRelayTxFee = "0.00001000";
/** The maximum number of bytes in OP_RETURN outputs that we're willing to relay/mine */
static const unsigned int MAX_OP_RETURN_RELAY = 80;

/** Declaration of Standard Policy implementing CPolicy */
class CStandardPolicy : public CPolicy
{
protected:
    unsigned nMaxDatacarrierBytes;
    bool fIsBareMultisigStd;
    bool fAllowFree;
    /** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
    CFeeRate minRelayTxFee;
public:
    CStandardPolicy() : nMaxDatacarrierBytes(MAX_OP_RETURN_RELAY),
                        fIsBareMultisigStd(true),
                        fAllowFree(true),
                        minRelayTxFee(1000)
    {};

    virtual void InitFromArgs(const std::map<std::string, std::string>&);
    virtual bool ValidateScript(const CScript&, txnouttype&) const;
    // "Dust" is defined in terms of minRelayTxFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more than 1/3 in fees
    // to spend something, then we consider it dust.
    // A typical txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a txout less than 546 satoshis 
    // with default minRelayTxFee.
    virtual bool ValidateOutput(const CTxOut& txout) const;
    virtual bool ValidateFee(const CAmount&, size_t) const;
    virtual bool ValidateFeeRate(const CFeeRate&) const;
    /** DEPRECATED: avoid using this method when possible */
    virtual const CFeeRate& GetMinRelayFeeRate() const;
    virtual bool ValidateTx(const CTransaction&, CValidationState&) const;
    /**
     * Check transaction inputs to mitigate two
     * potential denial-of-service attacks:
     * 
     * 1. scriptSigs with extra data stuffed into them,
     *    not consumed by scriptPubKey (or P2SH script)
     * 2. P2SH scripts with a crazy number of expensive
     *    CHECKSIG/CHECKMULTISIG operations
     */
    virtual bool ValidateTxInputs(const CTransaction& tx, const CCoinsViewEfficient& mapInputs) const;
    virtual bool ValidateTxFee(const CAmount&, size_t, const CTransaction&, int nHeight, bool fRejectAbsurdFee, bool fLimitFree, const CCoinsViewEfficient&, CTxMemPool&, CValidationState&) const;
    virtual bool BuildNewBlock(CBlockTemplate&, const CTxMemPool&, const CBlockIndex&, CCoinsViewCache&) const;
};

/** Default Policy for testnet and regtest */
class CTestPolicy : public CStandardPolicy 
{
public:
    virtual bool ValidateTx(const CTransaction& tx, std::string& reason) const
    {
        return true;
    }
    virtual bool ValidateTxInputs(const CTransaction& tx, const CCoinsViewEfficient& mapInputs) const
    {
        return true;
    }
};

/** Global variables and their interfaces */

static CStandardPolicy standardPolicy;
static CTestPolicy testPolicy;

static CPolicy* pCurrentPolicy = 0;

CPolicy& Policy(std::string policy)
{
    if (policy == "standard")
        return standardPolicy;
    else if (policy == "test")
        return testPolicy;
    throw std::runtime_error(strprintf(_("Unknown policy '%s'"), policy));
}

void SelectPolicy(std::string policy)
{
    pCurrentPolicy = &Policy(policy);
}

const CPolicy& Policy()
{
    assert(pCurrentPolicy);
    return *pCurrentPolicy;
}

std::string GetPolicyUsageStr()
{
    std::string strUsage = "";
    strUsage += "  -datacarrier           " + strprintf(_("Relay and mine data carrier transactions (default: %u)"), 1) + "\n";
    strUsage += "  -datacarriersize       " + strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), MAX_OP_RETURN_RELAY) + "\n";
    strUsage += "  -minrelaytxfee=<amt>   " + strprintf(_("Fees (in BTC/Kb) smaller than this are considered zero fee for relaying (default: %s)"), defaultMinRelayTxFee) + "\n";
    strUsage += "  -permitbaremultisig    " + strprintf(_("Relay non-P2SH multisig (default: %u)"), 1) + "\n";
    strUsage += "  -policy                " + strprintf(_("Select a specific type of policy (default: %s)"), "standard") + "\n";
    return strUsage;
}

void InitPolicyFromArgs(const std::map<std::string, std::string>& mapArgs)
{
    SelectPolicy(GetArg("-policy", Params().DefaultPolicy(), mapArgs));
    pCurrentPolicy->InitFromArgs(mapArgs);
}

/** CStandardPolicy implementation */

void CStandardPolicy::InitFromArgs(const std::map<std::string, std::string>& mapArgs)
{
    if (GetArg("-datacarrier", true, mapArgs))
        nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes, mapArgs);
    else
        nMaxDatacarrierBytes = 0;
    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    std::string strRelayFee = GetArg("-minrelaytxfee", defaultMinRelayTxFee, mapArgs);
    CAmount n = 0;
    if (ParseMoney(strRelayFee, n) && MoneyRange(n))
        minRelayTxFee = CFeeRate(n);
    else
        throw std::runtime_error(strprintf(_("Invalid amount for -minrelaytxfee=<amount>: '%s'"), strRelayFee));
    fIsBareMultisigStd = GetArg("-permitbaremultisig", fIsBareMultisigStd, mapArgs);
}

bool CStandardPolicy::ValidateScript(const CScript& scriptPubKey, txnouttype& whichType) const
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    switch (whichType)
    {
        case TX_MULTISIG:
        {
            unsigned char m = vSolutions.front()[0];
            unsigned char n = vSolutions.back()[0];
            // Support up to x-of-3 multisig txns as standard
            if (n < 1 || n > 3)
                return false;
            if (m < 1 || m > n)
                return false;
            break;
        }

        case TX_NULL_DATA:
            // TX_NULL_DATA without any vSolutions is a lone OP_RETURN, which traditionally is accepted regardless of the -datacarrier option, so we skip the check.
            // If you want to filter lone OP_RETURNs, be sure to handle vSolutions being empty below where vSolutions.front() is accessed!
            if (vSolutions.size())
            {
                if (!nMaxDatacarrierBytes)
                    return false;

                if (vSolutions.front().size() > nMaxDatacarrierBytes)
                    return false;
            }

            break;

        default:
            // no other restrictions on standard scripts
            break;
    }

    return whichType != TX_NONSTANDARD;
}

bool CStandardPolicy::ValidateOutput(const CTxOut& txout) const
{
    size_t nSize = txout.GetSerializeSize(SER_DISK,0) + 148u;
    return (txout.nValue < 3 * minRelayTxFee.GetFee(nSize));
}

bool CStandardPolicy::ValidateFee(const CAmount& nFees, size_t nSize) const
{
    return nFees >= minRelayTxFee.GetFee(nSize);
}

bool CStandardPolicy::ValidateFeeRate(const CFeeRate& rate) const
{
    return rate >= minRelayTxFee;
}

const CFeeRate& CStandardPolicy::GetMinRelayFeeRate() const
{
    return minRelayTxFee;
}

bool CStandardPolicy::ValidateTx(const CTransaction& tx, CValidationState& state) const
{
    if (tx.nVersion > CTransaction::CURRENT_VERSION || tx.nVersion < 1)
        return state.DoS(0, false, REJECT_NONSTANDARD, "version");

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE)
        return state.DoS(0, false, REJECT_NONSTANDARD, "tx-size");

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (tx.vin[i].scriptSig.size() > 1650)
            return state.DoS(0, false, REJECT_NONSTANDARD, "scriptsig-size");

        if (!tx.vin[i].scriptSig.IsPushOnly())
            return state.DoS(0, false, REJECT_NONSTANDARD, "scriptsig-not-pushonly");
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        if (!ValidateScript(tx.vout[i].scriptPubKey, whichType))
            return state.DoS(0, false, REJECT_NONSTANDARD, "scriptpubkey");

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if ((whichType == TX_MULTISIG) && (!fIsBareMultisigStd))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bare-multisig");
        else if (ValidateOutput(tx.vout[i]))
            return state.DoS(0, false, REJECT_NONSTANDARD, "dust");
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1)
        return state.DoS(0, false, REJECT_NONSTANDARD, "multi-op-return");

    return true;
}

bool CStandardPolicy::ValidateTxInputs(const CTransaction& tx, const CCoinsViewEfficient& mapInputs) const
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut& prev = mapInputs.GetOutputFor(tx.vin[i]);

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // Policy().ValidateTx() will have already returned false
        // and this method isn't called.
        std::vector<std::vector<unsigned char> > stack;
        if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker()))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            std::vector<std::vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
                if (tmpExpected < 0)
                    return false;
                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

bool CStandardPolicy::ValidateTxFee(const CAmount& nFees, size_t nSize, const CTransaction& tx, int nHeight, bool fRejectAbsurdFee, bool fLimitFree, const CCoinsViewEfficient& view, CTxMemPool& mempool, CValidationState& state) const
{
    bool fValidateFee = nFees >= minRelayTxFee.GetFee(nSize);
    if (fLimitFree && !fValidateFee) {
        double dPriorityDelta = 0;
        CAmount nFeeDelta = 0;
        mempool.ApplyDeltas(tx.GetHash(), dPriorityDelta, nFeeDelta);
        if (!(dPriorityDelta > 0 || nFeeDelta > 0 ||
              // There is a free transaction area in blocks created by most miners,
              // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
              //   to be considered to fall into this category. We don't want to encourage sending
              //   multiple transactions instead of one big transaction to avoid fees.
              (fAllowFree && nSize < DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
            return state.DoS(0, error("%s: not enough fees, %d < %d",
                                      __func__, nFees, minRelayTxFee.GetFee(nSize)),
                             REJECT_INSUFFICIENTFEE, "insufficient fee");

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000)
                return state.DoS(0, error("%s: free transaction rejected by rate limiter", __func__),
                                 REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }
    }

    // Require that free transactions have sufficient priority to be mined in the next block.
    if (GetBoolArg("-relaypriority", true) && !fValidateFee && !AllowFree(view.GetPriority(tx, nHeight + 1)))
        return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");

    if (fRejectAbsurdFee && nFees > minRelayTxFee.GetFee(nSize) * 10000)
        return error("%s: absurdly high fees %s, %d > %d", __func__,
                     nFees, minRelayTxFee.GetFee(nSize) * 10000);

    return true;
}

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    std::set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

bool CStandardPolicy::BuildNewBlock(CBlockTemplate& blocktemplate, const CTxMemPool& pool, const CBlockIndex& indexPrev, CCoinsViewCache& view) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    const int nNewBlockHeight = blocktemplate.nHeight;
    const uint64_t nBlockSize = blocktemplate.nBlockSize;

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Priority order to process transactions
    std::list<COrphan> vOrphan; // list memory doesn't move
    std::map<uint256, std::vector<COrphan*> > mapDependers;
    bool fPrintPriority = GetBoolArg("-printpriority", false);

    // This vector will be sorted into a priority queue:
    std::vector<TxPriority> vecPriority;
    vecPriority.reserve(mempool.mapTx.size());
    for (std::map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
         mi != mempool.mapTx.end(); ++mi)
    {
        const CTransaction& tx = mi->second.GetTx();
        if (tx.IsCoinBase() || !IsFinalTx(tx, nNewBlockHeight))
            continue;

        COrphan* porphan = NULL;
        double dPriority = 0;
        CAmount nTotalIn = 0;
        bool fMissingInputs = false;
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            // Read prev transaction
            if (!view.HaveCoins(txin.prevout.hash))
            {
                // This should never happen; all transactions in the memory
                // pool should connect to either transactions in the chain
                // or other transactions in the memory pool.
                if (!mempool.mapTx.count(txin.prevout.hash))
                {
                    LogPrintf("ERROR: mempool transaction missing input\n");
                    if (fDebug) assert("mempool transaction missing input" == 0);
                    fMissingInputs = true;
                    if (porphan)
                        vOrphan.pop_back();
                    break;
                }

                // Has to wait for dependencies
                if (!porphan)
                {
                    // Use list for automatic deletion
                    vOrphan.push_back(COrphan(&tx));
                    porphan = &vOrphan.back();
                }
                mapDependers[txin.prevout.hash].push_back(porphan);
                porphan->setDependsOn.insert(txin.prevout.hash);
                nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
                continue;
            }
            const CCoins* coins = view.AccessCoins(txin.prevout.hash);
            assert(coins);

            CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
            nTotalIn += nValueIn;

            int nConf = nNewBlockHeight - coins->nHeight;

            dPriority += (double)nValueIn * nConf;
        }
        if (fMissingInputs) continue;

        // Priority is sum(valuein * age) / modified_txsize
        unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        dPriority = tx.ComputePriority(dPriority, nTxSize);

        uint256 hash = tx.GetHash();
        mempool.ApplyDeltas(hash, dPriority, nTotalIn);

        CFeeRate feeRate(nTotalIn-tx.GetValueOut(), nTxSize);

        if (porphan)
        {
            porphan->dPriority = dPriority;
            porphan->feeRate = feeRate;
        }
        else
            vecPriority.push_back(TxPriority(dPriority, feeRate, &mi->second.GetTx()));
    }

    // Collect memory pool transactions into the block
    bool fSortedByFee = (nBlockPrioritySize <= 0);

    TxPriorityCompare comparer(fSortedByFee);
    std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

    while (!vecPriority.empty())
    {
        // Take highest priority transaction off the priority queue:
        double dPriority = vecPriority.front().get<0>();
        CFeeRate feeRate = vecPriority.front().get<1>();
        const CTransaction& tx = *(vecPriority.front().get<2>());

        std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
        vecPriority.pop_back();

        // Size limits
        unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        if (nBlockSize + nTxSize >= nBlockMaxSize)
            continue;

        // Skip free transactions if we're past the minimum block size:
        const uint256& hash = tx.GetHash();
        double dPriorityDelta = 0;
        CAmount nFeeDelta = 0;
        mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
        if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            continue;

        if (!blocktemplate.AddTransaction(tx, view))
            continue;

        if (fPrintPriority)
        {
            LogPrintf("priority %.1f fee %s txid %s\n",
                      dPriority, feeRate.ToString(), tx.GetHash().ToString());
        }

        // Add transactions that depend on this one to the priority queue
        if (mapDependers.count(hash))
        {
            for (unsigned i = 0; i < mapDependers[hash].size(); i++) {
                COrphan* porphan = mapDependers[hash][i];
                if (!porphan->setDependsOn.empty())
                {
                    porphan->setDependsOn.erase(hash);
                    if (porphan->setDependsOn.empty())
                    {
                        vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                    }
                }
            }
        }

        // Prioritise by fee once past the priority size or we run out of high-priority
        // transactions:
        if (!fSortedByFee &&
            ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
        {
            fSortedByFee = true;
            comparer = TxPriorityCompare(fSortedByFee);
            std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
        }
    }

    return true;
}
