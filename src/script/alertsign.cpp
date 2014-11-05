// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "script/generic.hpp"

bool AlertSignSignature(const CKeyStore& keystore, const CScript& scriptPubKey, CScript& scriptSig, CUnsignedAlert& alert)
{
    return TemplatedSignSignature(keystore, scriptPubKey, scriptSig, alert, SIGHASH_ALL);
}

CScript AlertCombineSignatures(CScript scriptPubKey, const CUnsignedAlert& alert, const CScript& scriptSig1, const CScript& scriptSig2)
{
    return TemplatedCombineSignatures(scriptPubKey, alert, scriptSig1, scriptSig2);
}

bool AlertVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const CUnsignedAlert& alert)
{
    return TemplatedVerifyScript(scriptSig, scriptPubKey, flags, alert);
}
