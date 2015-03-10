// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"

#include "coins.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/sigcache.h"
#include "tinyformat.h"
#include "util.h"
#include "utilmoneystr.h"
#include "version.h"

#include <boost/foreach.hpp>

bool CheckFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (!tx.vin[i].IsFinal())
            return false;
    return true;
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CTxOut &prevout = inputs.GetOutputFor(tx.vin[i]);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

CAmount Consensus::GetValueOut(const CTransaction& tx)
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(tx.vout.begin()); it != tx.vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!Consensus::VerifyAmount(it->nValue) || !Consensus::VerifyAmount(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

bool Consensus::CheckTx(const CTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        if (tx.vout[i].nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (tx.vout[i].nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += tx.vout[i].nValue;
        if (!Consensus::VerifyAmount(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    std::set<COutPoint> vInOutPoints;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        if (vInOutPoints.count(tx.vin[i].prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(tx.vin[i].prevout);
    }

    if (tx.IsCoinBase()) {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    } else {
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            if (tx.vin[i].prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!inputs.HaveInputs(tx))
            return state.Invalid(false, REJECT_INVALID, "bad-txns-inputs-unavailable");

        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            const COutPoint &prevout = tx.vin[i].prevout;
            const CCoins *coins = inputs.AccessCoins(prevout.hash);
            assert(coins);

            // If prev is coinbase, check that it's matured
            if (coins->IsCoinBase())
                if (nSpendHeight - coins->nHeight < COINBASE_MATURITY)
                    return state.Invalid(false, REJECT_INVALID, strprintf("bad-txns-premature-spend-of-coinbase (depth %d)", nSpendHeight - coins->nHeight));

            // Check for negative or overflow input values
            nValueIn += coins->vout[prevout.n].nValue;
            if (!Consensus::VerifyAmount(coins->vout[prevout.n].nValue) || !Consensus::VerifyAmount(nValueIn))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }

        CAmount nValueOut = Consensus::GetValueOut(tx);
        if (nValueIn < nValueOut)
            return state.DoS(100, false, REJECT_INVALID, strprintf("bad-txns-in-belowout (%s < %s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));

        // Tally transaction fees
        CAmount nTxFee = nValueIn - nValueOut;
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");

        nFees += nTxFee;
        if (!Consensus::VerifyAmount(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");

    return true;
}

unsigned int GetSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    return GetLegacySigOpCount(tx) + GetP2SHSigOpCount(tx, inputs);
}

bool Consensus::CheckTxInputsScripts(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, bool cacheStore, unsigned int flags)
{
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const CCoins* coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        const CScript& scriptPubKey = coins->vout[prevout.n].scriptPubKey;
        CachingTransactionSignatureChecker checker(&tx, i, cacheStore);
        ScriptError scriptError(SCRIPT_ERR_UNKNOWN_ERROR);
        if (!VerifyScript(scriptPubKey, tx.vin[i].scriptSig, flags, checker, &scriptError))
            return state.DoS(100, false, REJECT_INVALID, 
                             strprintf("script-verify-failed (in input %d: %s)", i, ScriptErrorString(scriptError)));
    }
    return true;
}

bool Consensus::VerifyTx(const CTransaction& tx, CValidationState &state, int nBlockHeight, int64_t nBlockTime, const CCoinsViewCache& inputs, int nSpendHeight, bool cacheStore, unsigned int flags)
{
    if (!CheckTx(tx, state))
        return false;
    if (!CheckFinalTx(tx, nBlockHeight, nBlockTime))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");
    if (!CheckTxInputs(tx, state, inputs, nSpendHeight))
        return false;
    if (GetSigOpCount(tx, inputs) > MAX_BLOCK_SIGOPS)
        return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops");
    if (!CheckTxInputsScripts(tx, state, inputs, cacheStore, flags))
        return false;        
    return true;
}
