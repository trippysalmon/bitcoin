// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_STORAGE_INTERFACES_CPP_H
#define BITCOIN_CONSENSUS_STORAGE_INTERFACES_CPP_H

#include "amount.h"
#include "interfaces.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <algorithm>

class CTransaction;
class CTxOut;

/**
 * Window of previous blocks to use for calculating the median time.
 * This constant is consensus critical.
 */
static const unsigned int MEDIAN_TIME_SPAN = 11;

// CPP storage interfaces

class CBlockIndexView
{
public:
    CBlockIndexView() {};
    virtual ~CBlockIndexView() {};

    virtual const uint256 GetBlockHash() const = 0;
    //! Efficiently find an ancestor of this block.
    virtual const CBlockIndexView* GetAncestorView(int64_t height) const = 0;
    virtual int64_t GetHeight() const = 0;
    virtual int32_t GetVersion() const = 0;
    virtual int32_t GetTime() const = 0;
    virtual int32_t GetBits() const = 0;
    // Potential optimizations
    virtual const CBlockIndexView* GetPrev() const
    {
        return GetAncestorView(GetHeight() - 1);
    };
    virtual int64_t GetMedianTimePast() const
    {
        int64_t pmedian[MEDIAN_TIME_SPAN];
        int64_t* pbegin = &pmedian[MEDIAN_TIME_SPAN];
        int64_t* pend = &pmedian[MEDIAN_TIME_SPAN];

        const CBlockIndexView* pindex = this;
        for (unsigned i = 0; i < MEDIAN_TIME_SPAN && pindex; i++, pindex = pindex->GetPrev())
            *(--pbegin) = pindex->GetTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }
};

class CCoinsInterface
{
public:
    CCoinsInterface() {};
    virtual ~CCoinsInterface() {};    

    //! check whether a particular output is still available or spent
    virtual bool IsAvailable(int32_t nPos) const = 0;
    virtual bool IsCoinBase() const = 0;
    //! check whether the entire CCoins is spent
    //! note that only !IsPruned() CCoins can be serialized
    virtual bool IsPruned() const = 0;
    virtual const CAmount& GetAmount(int32_t nPos) const = 0;
    virtual const CScript& GetScriptPubKey(int32_t nPos) const = 0;
    virtual int64_t GetHeight() const = 0;
};

class CUtxoView
{
public:
    CUtxoView() {};
    virtual ~CUtxoView() {};

    /**
     * Return a pointer to CCoins in the cache, or NULL if not found. This is
     * more efficient than GetCoins. Modifications to other cache entries are
     * allowed while accessing the returned pointer.
     */
    virtual const CCoinsInterface* AccessCoins(const uint256 &txid) const = 0;
};

// Interface translators

// Interface translators: from C to CPP

class CBlockIndexCPPViewFromCInterface : public CBlockIndexView
{
    const Consensus::BlockIndexInterface& interface;
    const void* indexObject;
public:
    CBlockIndexCPPViewFromCInterface(const Consensus::BlockIndexInterface& interfaceIn, const void* indexObjectIn) : 
        interface(interfaceIn), indexObject(indexObjectIn) 
    {}
    virtual ~CBlockIndexCPPViewFromCInterface() {}

    virtual int64_t GetHeight() const
    {
        return interface.Height(indexObject);
    }
    virtual int32_t GetVersion() const
    {
        return interface.Version(indexObject);
    }
    virtual int32_t GetTime() const
    {
        return interface.Time(indexObject);
    }
    virtual int32_t GetBits() const
    {
        return interface.Bits(indexObject);
    }
    //! Efficiently find an ancestor of this block.
    virtual const uint256 GetBlockHash() const
    {
        return interface.Hash(indexObject);
    }
    virtual const CBlockIndexView* GetAncestorView(int64_t height) const
    {
        return new CBlockIndexCPPViewFromCInterface(interface, interface.Ancestor(indexObject, height));
    }
    virtual const CBlockIndexView* GetPrev() const
    {
        if (interface.Prev == NULL) // No optimization implemented
            return this->GetAncestorView(this->GetHeight() - 1);
        return new CBlockIndexCPPViewFromCInterface(interface, interface.Prev(indexObject));
    }
    virtual int64_t GetMedianTimePast() const
    {
        if (interface.MedianTime == NULL) // No optimization implemented
            return CBlockIndexView::GetMedianTimePast();
        return interface.MedianTime(indexObject);
    }
};

// Interface translators: from CPP to C

namespace {
static const void* ChainAncestorGetter(const void* indexObject, const int64_t height)
{
    return ((const CBlockIndexView*)indexObject)->GetAncestorView(height);
}
static const uint256 ChainHashGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetBlockHash();
}
static int64_t ChainHeightGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetHeight();
}
static int32_t ChainVersionGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetVersion();
}
static int32_t ChainTimeGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetTime();
}
static int32_t ChainBitsGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetBits();
}
inline const void* ChainPrevGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetPrev();
}
inline int64_t ChainMedianTimeGetter(const void* indexObject)
{
    return ((const CBlockIndexView*)indexObject)->GetMedianTimePast();
}
static void ChainIndexDeallocator(void* indexObject)
{
    // Bitcoin Core keeps the index in memory: Don't free anything. 
}
} // Anonymous namespace 

/**
 * Bitcoin Core implementation of Consensus::BlockIndexInterface.
 */
struct ChainInterface : public Consensus::BlockIndexInterface
{
    ChainInterface()
    {
        Ancestor = ChainAncestorGetter;
        Hash = ChainHashGetter;
        Height = ChainHeightGetter;
        Version = ChainVersionGetter;
        Time = ChainTimeGetter;
        Bits = ChainBitsGetter;
        Prev = ChainPrevGetter;
        MedianTime = ChainMedianTimeGetter;
        deleteIndex = ChainIndexDeallocator;
    }

};
static const ChainInterface CHAIN_INTERFACE;

#endif // BITCOIN_CONSENSUS_STORAGE_INTERFACES_CPP_H
