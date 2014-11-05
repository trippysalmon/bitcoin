// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_GENERIC
#define H_BITCOIN_SCRIPT_GENERIC

#include "hash.h"
#include "key.h"
#include "keystore.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/interpreter.h"
#include "script/sign.h"

#include <vector>

using namespace std;

template<typename T>
uint256 SignatureHash(const CScript& scriptCode, const T& signable, int nHashType)
{
    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << signable << nHashType;
    return ss.GetHash();
}

template<typename T>
class TemplatedSignatureChecker : public BaseSignatureChecker
{
private:
    const T& signable;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    TemplatedSignatureChecker(const T& signableIn) : signable(signableIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const;
};

template<typename T>
bool TemplatedSignatureChecker<T>::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

template<typename T>
bool TemplatedSignatureChecker<T>::CheckSig(const vector<unsigned char>& vchSigIn, const vector<unsigned char>& vchPubKey, const CScript& scriptCode) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, signable, nHashType);

    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

template<typename T>
class TemplatedSignatureCreator : public BaseSignatureCreator {
    const T& signable;
    int nHashType;
    const TemplatedSignatureChecker<T> checker;

public:
    TemplatedSignatureCreator(const CKeyStore& keystoreIn, const T& signableIn, int nHashTypeIn=SIGHASH_ALL) : BaseSignatureCreator(keystoreIn), signable(signableIn), nHashType(nHashTypeIn), checker(TemplatedSignatureChecker<T>(signable)) {}
    const BaseSignatureChecker& Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const;
};

template<typename T>
bool TemplatedSignatureCreator<T>::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode) const
{
    CKey key;
    if (!keystore.GetKey(address, key))
        return false;

    uint256 hash = SignatureHash(scriptCode, signable, nHashType);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

template<typename T>
bool TemplatedSignSignature(const CKeyStore& keystore, const CScript& scriptPubKey, CScript& scriptSig, T& signable, int nHashType=SIGHASH_ALL)
{
    TemplatedSignatureCreator<T> creator(keystore, signable, nHashType);
    return ProduceSignature(creator, scriptPubKey, scriptSig);
}

template<typename T>
CScript TemplatedCombineSignatures(CScript scriptPubKey, const T& signable, const CScript& scriptSig1, const CScript& scriptSig2)
{
    TemplatedSignatureChecker<T> checker(signable);
    return CombineSignatures(scriptPubKey, checker, scriptSig1, scriptSig2);
}

template<typename T>
bool TemplatedVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const T& signable)
{
    TemplatedSignatureChecker<T> checker(signable);
    return VerifyScript(scriptSig, scriptPubKey, flags, checker);
}

#endif // H_BITCOIN_SCRIPT_GENERIC
