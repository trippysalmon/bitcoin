// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_SIGN_HPP
#define H_BITCOIN_SCRIPT_SIGN_HPP

#include "script_interpreter.hpp"
#include "script_standard.h"

#include "keystore.h"

typedef vector<unsigned char> valtype;

static bool Sign1(const CKeyID& address, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    CKey key;
    if (!keystore.GetKey(address, key))
        return false;

    vector<unsigned char> vchSig;
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;

    return true;
}

//
// Sign scriptPubKey with private keys stored in keystore, given transaction hash and hash type.
// Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
// unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
// Returns false if scriptPubKey could not be completely satisfied.
//
static bool SignSignature(const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet, const txnouttype& whichType, const vector<valtype>& vSolutions)
{
    scriptSigRet.clear();
    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
            return false;
        else
        {
            CPubKey vch;
            keystore.GetPubKey(keyID, vch);
            scriptSigRet << vch;
        }
        return true;
    case TX_MULTISIG:
        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        int nSigned = 0;
        int nRequired = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1 && nSigned < nRequired; i++)
        {
            const valtype& pubkey = vSolutions[i];
            CKeyID keyID = CPubKey(pubkey).GetID();
            if (Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
                ++nSigned;
        }
        return nSigned==nRequired;
    }
    return false;
}

template <typename T>
bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, T& tx, int nHashType, CScript& scriptSigRet)
{
    txnouttype whichType;
    vector<valtype> vSolutions;
    if (!Solver(fromPubKey, whichType, vSolutions))
        return false;

    bool fSolved;
    if (whichType == TX_SCRIPTHASH) {
        // The subscript found in the keystore is what needs to be evaluated
        if (!keystore.GetCScript(uint160(vSolutions[0]), subscript))
            return false;

        vSolutions.clear();
        fSolved = Solver(subscript, whichType, vSolutions) && whichType != TX_SCRIPTHASH;

        if (fSolved) {
            // use the subscript instead of the fromPubKey to compute txn hash:
            uint256 hash2 = tx.SignatureHash(subscript, nHashType);
            fSolved = SignSignature(keystore, hash2, nHashType, scriptSigRet, whichType, vSolutions);
        }
        // the final scriptSig is the signatures from the subscript and then
        // the serialized subscript whether or not it is completely signed
        scriptSigRet << static_cast<valtype>(subscript);
    } else {
        // Leave out the signature from the hash, since a signature can't sign itself.
        // The checksig op will also drop the signatures from its hash.
        uint256 hash = tx.SignatureHash(fromPubKey, nHashType);
        fSolved = SignSignature(keystore, hash, nHashType, scriptSigRet, whichType, vSolutions);
    }
    if (!fSolved) return false;
    // Test solution
    return VerifyScript(scriptSigRet, fromPubKey, tx, STANDARD_SCRIPT_VERIFY_FLAGS, 0);
}

template <typename T>
static CScript CombineMultisig(CScript scriptPubKey, const T& tx, const vector<valtype>& vSolutions, vector<valtype>& sigs1, vector<valtype>& sigs2)
{
    // Combine all the signatures we've got:
    set<valtype> allsigs;
    BOOST_FOREACH(const valtype& v, sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    BOOST_FOREACH(const valtype& v, sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    map<valtype, valtype> sigs;
    BOOST_FOREACH(const valtype& sig, allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (CheckSig(sig, pubkey, scriptPubKey, tx, 0, 0))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    CScript result; result << OP_0; // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result << sigs[vSolutions[i+1]];
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result << OP_0;

    return result;
}

static CScript PushAll(const vector<valtype>& values)
{
    CScript result;
    BOOST_FOREACH(const valtype& v, values)
        result << v;
    return result;
}

template <typename T>
static CScript CombineSignatures(CScript scriptPubKey, const T& tx, const txnouttype txType, const vector<valtype>& vSolutions, vector<valtype>& sigs1, vector<valtype>& sigs2)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if (sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if (sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else
        {
            // Recur to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(pubKey2, tx, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, tx, vSolutions, sigs1, sigs2);
    }

    return CScript();
}

template <typename T>
CScript CombineSignatures(CScript scriptPubKey, const T& tx, const T& emptyTx, const CScript& scriptSig1, const CScript& scriptSig2)
{
    txnouttype txType;
    vector<vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    vector<valtype> stack1;
    EvalScript(stack1, scriptSig1, emptyTx, SCRIPT_VERIFY_STRICTENC, 0);
    vector<valtype> stack2;
    EvalScript(stack2, scriptSig2, emptyTx, SCRIPT_VERIFY_STRICTENC, 0);

    return CombineSignatures(scriptPubKey, tx, txType, vSolutions, stack1, stack2);
}

#endif
