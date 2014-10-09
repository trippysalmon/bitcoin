// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/txhasher.h"

#include "script/txserializer.hpp"

uint256 TxSignatureHasher::SignatureHash(const CScript& scriptCode, int nHashType) const
{
    return TxSignatureHash<CTransaction, CTxOut>(scriptCode, txTo, nIn, nHashType);
}
