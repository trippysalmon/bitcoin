// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/checker.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/txserializer.hpp"
#include "uint256.h"
#include "util.h"

using namespace std;

namespace {

class COutPoint
{
public:
    uint256 hash;
    uint32_t n;
    COutPoint() { hash = 0; n = (uint32_t) -1; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(FLATDATA(*this));
    }
};

class CTxIn
{
public:
    COutPoint prevout;
    uint32_t nSequence;
    CTxIn() {}
};

class CTxOut
{
public:
    int64_t nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    }
};

class CTransaction
{
public:
    static const int32_t CURRENT_VERSION=1;
    const int32_t nVersion;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;
    CTransaction() : nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0) { }
};

class TxSignatureHasher : public SignatureHasher
{
private:
    const CTransaction txTo;
    unsigned int nIn;
public:
    TxSignatureHasher(const CTransaction& txToIn, unsigned int nInIn) : txTo(txToIn), nIn(nInIn) {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const
    {
        return TxSignatureHash<CTransaction, CTxOut>(scriptCode, txTo, nIn, nHashType);
    }
};

} // anon namespace

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, unsigned int flags)
{
    const TxSignatureHasher hasher(txTo, nIn);
    const SignatureChecker checker(hasher);
    return  VerifyScript(scriptSig, scriptPubKey, flags, checker);
}
