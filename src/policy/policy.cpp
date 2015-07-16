// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include "policy/policy.h"

#include "consensus/validation.h"
#include "main.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/foreach.hpp>

    /**
     * Check transaction inputs to mitigate two
     * potential denial-of-service attacks:
     * 
     * 1. scriptSigs with extra data stuffed into them,
     *    not consumed by scriptPubKey (or P2SH script)
     * 2. P2SH scripts with a crazy number of expensive
     *    CHECKSIG/CHECKMULTISIG operations
     *
     * Check transaction inputs, and make sure any
     * pay-to-script-hash transactions are evaluating IsStandard scripts
     * 
     * Why bother? To avoid denial-of-service attacks; an attacker
     * can submit a standard HASH... OP_EQUAL transaction,
     * which will get accepted into blocks. The redemption
     * script can be anything; an attacker could use a very
     * expensive-to-check-upon-redemption script like:
     *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
     */

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_MULTISIG)
    {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3)
            return false;
        if (m < 1 || m > n)
            return false;
    }

    return whichType != TX_NONSTANDARD;
}

bool IsStandardTx(const CTransaction& tx, std::string& reason)
{
    if (tx.nVersion > CTransaction::CURRENT_VERSION || tx.nVersion < 1) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE) {
        reason = "tx-size";
        return false;
    }

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if ((whichType == TX_MULTISIG) && (!fIsBareMultisigStd)) {
            reason = "bare-multisig";
            return false;
        } else if (txout.IsDust(::minRelayTxFee)) {
            reason = "dust";
            return false;
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

static bool AllowBelowMinRelayFee(CTxMemPool& pool, const uint256& hash, unsigned int nBytes)
{
    bool fAllowFree = true;
    double dPriorityDelta = 0;
    CAmount nFeeDelta = 0;
    pool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
    if (dPriorityDelta > 0 || nFeeDelta > 0)
        return true;

    // There is a free transaction area in blocks created by most miners,
    // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
    //   to be considered to fall into this category. We don't want to encourage sending
    //   multiple transactions instead of one big transaction to avoid fees.
    if (fAllowFree && nBytes < (DEFAULT_BLOCK_PRIORITY_SIZE - 1000))
        return true;

    return false;
}

bool AreInputsStandard(const CTransaction& tx, CValidationState &state, const CCoinsViewCache& mapInputs, const CAmount& nFees, const CAmount& nFeesDeleted, size_t nSize, bool fLimitFree, bool fRejectAbsurdFee)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    uint256 hash = tx.GetHash();
    if (fLimitFree && nFees - nFeesDeleted < ::minRelayTxFee.GetFee(nSize)) {

        // Don't accept it if it can't get into a block
        if (!AllowBelowMinRelayFee(mempool, hash, nSize))
            return state.DoS(0, error("AcceptToMemoryPool: not enough fees %s, %d < %d",
                                      hash.ToString(), nFees, ::minRelayTxFee.GetFee(nSize) + nFeesDeleted),
                             REJECT_INSUFFICIENTFEE, "insufficient fee");

        // Require that free transactions have sufficient priority to be mined in the next block.
        if (GetBoolArg("-relaypriority", true) && !AllowFree(mapInputs.GetPriority(tx, chainActive.Height() + 1)))
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient priority");

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
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
            return state.DoS(0, error("AcceptToMemoryPool: free transaction rejected by rate limiter"),
                             REJECT_INSUFFICIENTFEE, "rate limited free transaction");
        LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
    }

    if (fRejectAbsurdFee && nFees > ::minRelayTxFee.GetFee(nSize) * 10000)
        return error("AcceptToMemoryPool: absurdly high fees %s, %d > %d",
                     hash.ToString(),
                     nFees, ::minRelayTxFee.GetFee(nSize) * 10000);

    // Check that the transaction doesn't have an excessive number of
    // sigops, making it impossible to mine. Since the coinbase transaction
    // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
    // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
    // merely non-standard transaction.
    unsigned int nSigOps = GetLegacySigOpCount(tx);
    nSigOps += GetP2SHSigOpCount(tx, mapInputs);
    if (nSigOps > MAX_STANDARD_TX_SIGOPS)
        return state.DoS(0,
                         error("AcceptToMemoryPool: too many sigops %s, %d > %d",
                               hash.ToString(), nSigOps, MAX_STANDARD_TX_SIGOPS),
                         REJECT_NONSTANDARD, "bad-txns-too-many-sigops");

    if (!fRequireStandard)
        return true;

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
        // IsStandardTx() will have already returned false
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
