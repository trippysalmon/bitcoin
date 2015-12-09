// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_STRUCTS_H
#define BITCOIN_CONSENSUS_STRUCTS_H

#include "uint256.h"

struct CBaseBlockIndex
{
    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
    //! height of the entry in the chain. The genesis block has height 0
    int nHeight;
};

/**
 * Function pointer definition for libconsensus to interface with
 * chain index storage (and avoid CBlockIndex).
 */
typedef CBaseBlockIndex* (*PrevIndexGetter)(const CBaseBlockIndex*);
typedef CBaseBlockIndex* (*SkipIndexGetter)(const CBaseBlockIndex*);

#endif // BITCOIN_CONSENSUS_STRUCTS_H
