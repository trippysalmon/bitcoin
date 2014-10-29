// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits);
/** Scans nonces looking for a hash with at least some zero bits */
bool GenerateProof(CBlockHeader* pblock);
void ResetProof(CBlockHeader& block);
arith_uint256 GetBlockProof(const CBlockIndex& block);
bool CheckChallenge(const CBlockHeader& block, const CBlockIndex& indexLast);
void ResetChallenge(CBlockHeader& block, const CBlockIndex& indexLast);

/** Avoid using these functions when possible */
double GetChallengeDifficulty(const CBlockIndex* blockindex);

#endif // BITCOIN_POW_H
