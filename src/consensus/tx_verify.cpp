// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus.h"

#include "primitives/transaction.h"
#include "validation.h"

bool Consensus::VerifyTx(const CTransaction& tx, CValidationState& state, const int64_t flags)
{
    return true;
}
