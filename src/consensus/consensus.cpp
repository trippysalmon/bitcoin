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
#include "storage_interfaces_cpp.h"
#include "tinyformat.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "version.h"

#include <boost/foreach.hpp>

/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
static bool IsSuperMajority(int minVersion, const CBlockIndexView* pstart, unsigned nRequired, const Consensus::Params& consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->GetVersion() >= minVersion)
            ++nFound;
        pstart = pstart->GetPrev();
    }
    return (nFound >= nRequired);
}

unsigned int GetConsensusFlags(const CBlockHeader& block, const Consensus::Params& consensusParams, const CBlockIndexView* pindex, bool fNewBlock)
{
    // BIP16 didn't become active until Apr 1 2012
    bool fStrictPayToScriptHash = pindex->GetTime() >= 1333238400;
    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Old softforks with IsSuperMajority: start enforcing in new version blocks when 75% of the network has upgraded:

    // Start enforcing height in coinbase (BIP34), for block.nVersion=2
    if (block.nVersion >= 2 && IsSuperMajority(2, pindex, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
        flags |= TX_COINBASE_VERIFY_BIP34;

    // Start enforcing the DERSIG (BIP66) rules, for block.nVersion=3 blocks,
    if (block.nVersion >= 3 && IsSuperMajority(3, pindex->GetPrev(), consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
        flags |= SCRIPT_VERIFY_DERSIG;

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
    if (block.nVersion >= 4 && IsSuperMajority(4, pindex->GetPrev(), consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
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
    bool fEnforceBIP30 = !((pindex->GetHeight()==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
          (pindex->GetHeight()==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    if (fEnforceBIP30) {
        const CBlockIndexView* pindexBIP34height = pindex->GetAncestorView(consensusParams.BIP34Height);
        //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
        if (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == consensusParams.BIP34Hash))
            flags |= TX_VERIFY_BIP30;
    }

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

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
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

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CUtxoView& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CCoinsInterface* coins = inputs.AccessCoins(tx.vin[i].prevout.hash);
        const CScript& prevoutScript = coins->GetScriptPubKey(tx.vin[i].prevout.n);
        if (prevoutScript.IsPayToScriptHash())
            nSigOps += prevoutScript.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

//! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
bool CheckTxHasInputs(const CTransaction& tx, const CUtxoView& inputs)
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const COutPoint& prevout = tx.vin[i].prevout;
            const CCoinsInterface* coins = inputs.AccessCoins(prevout.hash);
            if (!coins || !coins->IsAvailable(prevout.n))
                return false;
        }
    }
    return true;
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
    std::set<COutPoint> vInOutPoints;
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

bool Consensus::CheckTxPreInputs(const CTransaction& tx, CValidationState& state, const int nHeight, int64_t nLockTimeCutoff, int64_t& nSigOps)
{
    if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");

    if (!CheckTransaction(tx, state))
        return false;

    nSigOps += GetLegacySigOpCount(tx);
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", "too many sigops");

    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndexView& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestorView(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndexView& block, std::pair<int, int64_t> lockPair)
{
    assert(block.GetPrev());
    int64_t nBlockTime = block.GetPrev()->GetMedianTimePast();
    if (lockPair.first >= block.GetHeight() || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndexView& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const unsigned int flags, const CUtxoView& inputs, const int64_t nSpendHeight, CAmount& nFees, int64_t& nSigOps)
{
    if (!CheckTxHasInputs(tx, inputs))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent");

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {

        const COutPoint &prevout = tx.vin[i].prevout;
        const CCoinsInterface* coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        // If prev is coinbase, check that it's matured
        if (coins->IsCoinBase()) {
            if (nSpendHeight - coins->GetHeight() < COINBASE_MATURITY)
                return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                                     strprintf("tried to spend coinbase at depth %d", nSpendHeight - coins->GetHeight()));
        }

        // Check for negative or overflow input values
        const CAmount& outputAmount = coins->GetAmount(prevout.n);
        nValueIn += outputAmount;
        if (!MoneyRange(outputAmount) || !MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }

    CAmount nValueOut = tx.GetValueOut();
    if (nValueIn < nValueOut)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                         strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOut)));

    // Tally transaction fees
    CAmount nTxFee = nValueIn - nValueOut;
    nFees += nTxFee;
    if (!MoneyRange(nTxFee))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");

    // Add in sigops done by pay-to-script-hash inputs;
    // this is to prevent a "rogue miner" from creating
    // an incredibly-expensive-to-validate block.
    if (flags & SCRIPT_VERIFY_P2SH)
        nSigOps += GetP2SHSigOpCount(tx, inputs);
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops");

    return true;
}

bool Consensus::CheckTxInputsScripts(const CTransaction& tx, CValidationState& state, const CUtxoView& inputs, unsigned int flags, bool cacheStore)
{
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const CCoinsInterface* coins = inputs.AccessCoins(prevout.hash);
        assert(coins);

        const CScript& scriptSig = tx.vin[i].scriptSig;
        const CScript& scriptPubKey = coins->GetScriptPubKey(prevout.n);
        CachingTransactionSignatureChecker checker(&tx, i, cacheStore);
        ScriptError error;

        if (!VerifyScript(scriptSig, scriptPubKey, flags, checker, &error))
            return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(error)));
    }

    return true;
}

bool Consensus::CheckTxCoinbase(const CTransaction& tx, CValidationState& state, unsigned flags, const int64_t nHeight)
{
    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    if (flags & TX_COINBASE_VERIFY_BIP34) {
        const CScript coinbaseSigScript = tx.vin[0].scriptSig;
        CScript expect = CScript() << nHeight;
        if (coinbaseSigScript.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), coinbaseSigScript.begin()))
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
    }

    return true;
}

bool Consensus::VerifyTx(const CTransaction& tx, CValidationState& state, const unsigned int flags, const int nHeight, const int64_t nMedianTimePast, const int64_t nBlockTime, bool fScriptChecks, bool cacheStore, const CBlockIndexView* pindexPrev, const CUtxoView& inputs, CAmount& nFees, int64_t& nSigOps)
{
    const int64_t nLockTimeCutoff = (flags & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : nBlockTime;
    if (!CheckTxPreInputs(tx, state, nHeight, nLockTimeCutoff, nSigOps))
        return false;

    // This could be moved to Consensus::VerifyCoinbaseTx() as an
    // optimization, but in a strict sense that would be a hardfork
    if (flags & TX_VERIFY_BIP30) { 
        const CCoinsInterface* coins = inputs.AccessCoins(tx.GetHash());
        if (coins && !coins->IsPruned())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-BIP30");
    }

    if (tx.IsCoinBase())
        return CheckTxCoinbase(tx, state, flags, nHeight);

    // Check that transaction is BIP68 final
    // BIP68 lock checks (as opposed to nLockTime checks) must
    // be in ConnectBlock because they require the UTXO set
    std::vector<int> prevHeights;
    prevHeights.resize(tx.vin.size());
    for (size_t j = 0; j < tx.vin.size(); j++)
        prevHeights[j] = inputs.AccessCoins(tx.vin[j].prevout.hash)->GetHeight();
    if (!SequenceLocks(tx, flags, &prevHeights, *pindexPrev))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-bip68-nonfinal");

    if (!Consensus::CheckTxInputs(tx, state, flags, inputs, nHeight, nFees, nSigOps))
        return false;

    if (fScriptChecks && !CheckTxInputsScripts(tx, state, inputs, flags, cacheStore))
        return false;

    return true;
}

bool Consensus::CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, int64_t nTime, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    // Check timestamp
    if (block.GetBlockTime() > nTime + 2 * 60 * 60)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

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
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0].IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i].IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
        if (!CheckTransaction(tx, state))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx.GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool Consensus::ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, const CBlockIndexView* pindexPrev)
{
    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    for (int32_t version = 2; version < 5; ++version) // check for version 2, 3 and 4 upgrades
        if (block.nVersion < version && IsSuperMajority(version, pindexPrev, consensusParams.nMajorityRejectBlockOutdated, consensusParams))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(v%d)", version - 1),
                                 strprintf("rejected nVersion=%d block", version - 1));

    return true;
}

bool Consensus::VerifyBlockHeader(const CBlockHeader& block, CValidationState& state, const Params& consensusParams, int64_t nTime, const CBlockIndexView* pindexPrev, bool fCheckPOW)
{
    if (!CheckBlockHeader(block, state, consensusParams, nTime, fCheckPOW))
        return false;

    if (!ContextualCheckBlockHeader(block, state, consensusParams, pindexPrev))
        return false;

    return true;
}
