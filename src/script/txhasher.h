// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_TXHASHER
#define H_BITCOIN_SCRIPT_TXHASHER

#include "core.h"
#include "script/checker.h"

class CScript;
class uint256;

class TxSignatureHasher : public SignatureHasher
{
private:
    const CTransaction txTo;
    unsigned int nIn;
public:
    TxSignatureHasher(const CTransaction& txToIn, unsigned int nInIn) : txTo(txToIn), nIn(nInIn) {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const;
};

#endif // H_BITCOIN_SCRIPT_TXHASHER
