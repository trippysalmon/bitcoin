// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_INTERFACES_H
#define BITCOIN_CONSENSUS_INTERFACES_H

#include <stdint.h>

class uint256; // TODO replace for something compatible with a C API

namespace Consensus {

typedef const uint256 (*HashGetter)(const void* indexObject);
typedef const void* (*AncestorGetter)(const void* indexObject, const int64_t height);
typedef int64_t (*HeightGetter)(const void* indexObject);
typedef int32_t (*VersionGetter)(const void* indexObject);
typedef int32_t (*TimeGetter)(const void* indexObject);
typedef int32_t (*BitsGetter)(const void* indexObject);

// Potential optimizations:

/**
 * Some implementations may chose to store a pointer to the previous
 * block instead of calling AncestorGetter, trading memory for
 * validation speed.
 */
typedef const void* (*PrevGetter)(const void* indexObject);
/**
 * Some implementations may chose to cache the Median Time Past.
 */
typedef int64_t (*MedianTimeGetter)(const void* indexObject);
/**
 * While not using this, it is assumed that the caller - who is
 * responsible for all the new allocations - will free all the memory
 * (or not) of the things that have been newly created in memory (or
 * not) after the call to the exposed libbitcoinconsenus function.
 * This function is mostly here to document the fact that some storage
 * optimizations are only possible if there's a fast signaling from
 * libbitcoinconsenus when data resources that have been asked for as
 * part of the validation are no longer needed. 
 */
typedef void (*IndexDeallocator)(void* indexObject);

/**
 * Collection of function pointers to interface with block index storage.
 */
struct BlockIndexInterface
{
    HashGetter Hash;
    AncestorGetter Ancestor;
    HeightGetter Height;
    VersionGetter Version;
    TimeGetter Time;
    BitsGetter Bits;
    /**
     * Just for optimization: If this is set to NULL, Ancestor() and
     * Height() will be called instead.
     */
    PrevGetter Prev;
    /**
     * Just for optimization: If this is set to NULL, Prev() and
     * Time() will be called instead.
     */
    MedianTimeGetter MedianTime;
    //! TODO This is mostly here for discussion, but not used yet.
    IndexDeallocator deleteIndex;
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_INTERFACES_H
