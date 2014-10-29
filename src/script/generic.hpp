// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_GENERIC
#define H_BITCOIN_SCRIPT_GENERIC

#include "hash.h"
#include "script/interpreter.h"
#include "script/sign.h"

template<typename T>
class GenericHasher : public SignatureHasher
{
private:
    const T data;
public:
    GenericHasher(const T& dataIn) : data(dataIn) {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const
    {
        // Serialize and hash
        CHashWriter ss(SER_GETHASH, 0);
        ss << data << nHashType;
        return ss.GetHash();
    }
};

template<typename T>
bool TemplatedVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const T& data)
{
    GenericHasher<T> hasher(data);
    GenericSignatureChecker checker(&hasher);
    return VerifyScript(scriptSig, scriptPubKey, flags, checker);
}

template<typename T>
bool TemplatedSignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CScript& scriptSigRet, const T& data, int nHashType)
{
    GenericHasher<T> hasher(data);
    return SignSignature(keystore, fromPubKey, hasher, nHashType, scriptSigRet);
}

template<typename T>
CScript TemplatedCombineSignatures(CScript scriptPubKey, const T& data, const CScript& scriptSig1, const CScript& scriptSig2)
{
    GenericHasher<T> hasher(data);
    return CombineSignatures(scriptPubKey, hasher, scriptSig1, scriptSig2);
}

#endif // H_BITCOIN_SCRIPT_GENERIC
