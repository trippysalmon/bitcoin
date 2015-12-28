// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus.h"

#include "merkle.h"
#include "pow.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/sigcache.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "version.h"

// TODO remove the following dependencies
#include "chain.h"
#include "coins.h"

#include <boost/foreach.hpp>

using namespace std;

/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

unsigned int GetConsensusFlags(const CBlockHeader& block, const Consensus::Params& consensusParams, const CBlockIndex* pindex, bool fNewBlock)
{
    // BIP16 didn't become active until Apr 1 2012
    bool fStrictPayToScriptHash = pindex->GetBlockTime() >= 1333238400;
    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Old softforks with IsSuperMajority: start enforcing in new version blocks when 75% of the network has upgraded:

    // Start enforcing height in coinbase (BIP34), for block.nVersion=2
    if (block.nVersion >= 2 && IsSuperMajority(2, pindex, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
        flags |= COINBASE_VERIFY_BIP34;

    // Start enforcing the DERSIG (BIP66) rules, for block.nVersion=3 blocks,
    if (block.nVersion >= 3 && IsSuperMajority(3, pindex->pprev, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
        flags |= SCRIPT_VERIFY_DERSIG;

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
    if (block.nVersion >= 4 && IsSuperMajority(4, pindex->pprev, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = fNewBlock || // Enforce on CreateNewBlock invocations.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(consensusParams.BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    if (fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == consensusParams.BIP34Hash)))
        flags |= VERIFY_TX_BIP30;

    return flags;
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

int64_t GetLockTimeCutoff(const CBlockHeader& block, const CBlockIndex* pindexPrev, const unsigned int flags)
{    
    return (flags & LOCKTIME_MEDIAN_TIME_PAST) ? pindexPrev->GetMedianTimePast() : block.GetBlockTime();
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        if (!txin.IsFinal())
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

bool CheckTransaction(const CTransaction& tx, CValidationState &state)
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
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int64_t nSpendHeight, CAmount& nFees)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(false, REJECT_DUPLICATE, "bad-txns-inputs-spent");

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {

        const COutPoint &prevout = tx.vin[i].prevout;
        const CCoins *coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        // If prev is coinbase, check that it's matured
        if (coins->IsCoinBase()) {
            if (nSpendHeight - coins->nHeight < COINBASE_MATURITY)
                return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                                     strprintf("tried to spend coinbase at depth %d", nSpendHeight - coins->nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coins->vout[prevout.n].nValue;
        if (!MoneyRange(coins->vout[prevout.n].nValue) || !MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }

    // Tally transaction fees
    CAmount nValueOut = tx.GetValueOut();
    if (nValueIn < nValueOut)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                         strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));

    CAmount nTxFee = nValueIn - nValueOut;
    if (!MoneyRange(nTxFee))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");

    nFees += nTxFee;
    return true;
}

bool Consensus::CheckTxInputsScripts(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheStore)
{
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const CCoins* coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        const CScript& scriptSig = tx.vin[i].scriptSig;
        const CScript& scriptPubKey = coins->vout[prevout.n].scriptPubKey;
        CachingTransactionSignatureChecker checker(&tx, i, cacheStore);
        ScriptError error;
        
        if (!VerifyScript(scriptSig, scriptPubKey, flags, checker, &error))
            return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(error)));
    }

    return true;
}

bool Consensus::CheckNonCoinbaseTxStorage(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int64_t nSpendHeight, unsigned int flags, bool fScriptChecks, bool cacheStore, CAmount& nFees, int64_t& nSigOps)
{
    if (!Consensus::CheckTxInputs(tx, state, inputs, nSpendHeight, nFees))
        return false;

    nSigOps += GetLegacySigOpCount(tx);
    // Add in sigops done by pay-to-script-hash inputs;
    // this is to prevent a "rogue miner" from creating
    // an incredibly-expensive-to-validate block.
    if (flags & SCRIPT_VERIFY_P2SH)
        nSigOps += GetP2SHSigOpCount(tx, inputs);
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops");

    if (fScriptChecks && !CheckTxInputsScripts(tx, state, inputs, flags, cacheStore))
        return false;

    return true;
}

bool Consensus::VerifyCoinbaseTx(const CTransaction& tx, CValidationState& state, const int64_t nHeight, unsigned flags, int64_t& nSigOps)
{
    nSigOps += GetLegacySigOpCount(tx);
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops");

    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    if (flags & COINBASE_VERIFY_BIP34) {
        const CScript coinbaseSigScript = tx.vin[0].scriptSig;
        CScript expect = CScript() << nHeight;
        if (coinbaseSigScript.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), coinbaseSigScript.begin()))
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height");
    }

    return true;
}

bool Consensus::VerifyTx(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const int64_t nHeight, const int64_t nSpendHeight, const int64_t nLockTimeCutoff, unsigned int flags, bool fScriptChecks, bool cacheStore, CAmount& nFees, int64_t& nSigOps)
{
    if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal");

    if (!CheckTransaction(tx, state))
        return false;

    if (flags & VERIFY_TX_BIP30) {
        const CCoins* coins = inputs.AccessCoins(tx.GetHash());
        if (coins && !coins->IsPruned())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-BIP30");
    }

    if (tx.IsCoinBase())
        return VerifyCoinbaseTx(tx, state, nHeight, flags, nSigOps);
    return CheckNonCoinbaseTxStorage(tx, state, inputs, nSpendHeight, flags, fScriptChecks, cacheStore, nFees, nSigOps);
}

bool Consensus::CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, int64_t nTime, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash");

    // Check timestamp
    if (block.GetBlockTime() > nTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new");

    return true;
}

bool Consensus::CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, int64_t nTime, bool fCheckPOW, bool fCheckMerkleRoot)
{
    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, nTime, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true);

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i].IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool Consensus::ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, const CBlockIndex* pindexPrev)
{
    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    for (int32_t version = 2; version < 5; ++version) // check for version 2, 3 and 4 upgrades
        if (block.nVersion < version && IsSuperMajority(version, pindexPrev, consensusParams.nMajorityRejectBlockOutdated, consensusParams))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(v%d)", version - 1));

    return true;
}

bool Consensus::VerifyBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, const CBlockIndex* pindexPrev, bool fCheckPOW)
{
    if (!CheckBlockHeader(block, state, consensusParams, nTime, fCheckPOW))
        return false;

    if (!ContextualCheckBlockHeader(block, state, consensusParams, pindexPrev))
        return false;

    return true;
}

bool Consensus::VerifyBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, int64_t nTime, const int64_t nSpendHeight, const CBlockIndex* pindexPrev, const CCoinsViewCache& inputs, bool fNewBlock, bool fScriptChecks, bool cacheStore, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, consensusParams, pindexPrev))
        return false;
    if (!CheckBlock(block, state, consensusParams, nTime, fCheckPOW))
        return false;

    unsigned int flags = GetConsensusFlags(block, consensusParams, pindexPrev, fNewBlock);
    const int64_t nLockTimeCutoff = GetLockTimeCutoff(block, pindexPrev, flags);
    const uint64_t nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    CAmount nFees = 0;
    int64_t nSigOps = 0;
    for (unsigned int i = 0; i < block.vtx.size(); i++)
        if (!VerifyTx(block.vtx[i], state, inputs, nHeight, nSpendHeight, nLockTimeCutoff, flags, fScriptChecks, cacheStore, nFees, nSigOps))
            return false;
    
    const CAmount blockReward = nFees + GetBlockSubsidy(pindexPrev->nHeight, consensusParams); 
    if (block.vtx[0].GetValueOut() > blockReward)
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-amount");

    return true;
}
