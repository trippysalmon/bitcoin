// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bitcoinconsensus.h"

#include "consensus/consensus.h"
#include "consensus/storage_interfaces_cpp.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "version.h"

namespace {

/** A class that deserializes a single object implementing ::Unserialize() one time. */
class ObjectInputStream
{
public:
    ObjectInputStream(int nTypeIn, int nVersionIn, const unsigned char *object, size_t objectLen) :
    m_type(nTypeIn),
    m_version(nVersionIn),
    m_data(object),
    m_remaining(objectLen)
    {}

    ObjectInputStream& read(char* pch, size_t nSize)
    {
        if (nSize > m_remaining)
            throw std::ios_base::failure(std::string(__func__) + ": end of data");

        if (pch == NULL)
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");

        if (m_data == NULL)
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");

        memcpy(pch, m_data, nSize);
        m_remaining -= nSize;
        m_data += nSize;
        return *this;
    }

    template<typename T>
    ObjectInputStream& operator>>(T& obj)
    {
        ::Unserialize(*this, obj, m_type, m_version);
        return *this;
    }

private:
    const int m_type;
    const int m_version;
    const unsigned char* m_data;
    size_t m_remaining;
};

inline int set_error(bitcoinconsensus_error* ret, bitcoinconsensus_error serror)
{
    if (ret)
        *ret = serror;
    return 0;
}

struct ECCryptoClosure
{
    ECCVerifyHandle handle;
};

ECCryptoClosure instance_of_eccryptoclosure;
}

int bitcoinconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, bitcoinconsensus_error* err)
{
    try {
        ObjectInputStream stream(SER_NETWORK, PROTOCOL_VERSION, txTo, txToLen);
        CTransaction tx;
        stream >> tx;
        if (nIn >= tx.vin.size())
            return set_error(err, bitcoinconsensus_ERR_TX_INDEX);
        if (tx.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) != txToLen)
            return set_error(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);

         // Regardless of the verification result, the tx did not error.
         set_error(err, bitcoinconsensus_ERR_OK);

        return VerifyScript(tx.vin[nIn].scriptSig, CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen), flags, TransactionSignatureChecker(&tx, nIn), NULL);
    } catch (const std::exception&) {
        return set_error(err, bitcoinconsensus_ERR_TX_DESERIALIZE); // Error deserializing
    }
}

int bitcoinconsensus_verify_header(const unsigned char* blockHeader, unsigned int blockHeaderLen,
                                   const Consensus::Params& consensusParams, int64_t nTime, void* pindexPrev, const Consensus::BlockIndexInterface& indexInterface, 
                                   bitcoinconsensus_error* err)
{
    try {
        ObjectInputStream stream(SER_NETWORK, PROTOCOL_VERSION, blockHeader, blockHeaderLen);
        CBlockHeader header;
        stream >> header;
        if (header.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) != blockHeaderLen)
            return set_error(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);

         // Regardless of the verification result, the tx did not error.
         set_error(err, bitcoinconsensus_ERR_OK);

         CValidationState state;
         return Consensus::VerifyBlockHeader(header, state, consensusParams, nTime, pindexPrev, indexInterface);
    } catch (const std::exception&) {
        return set_error(err, bitcoinconsensus_ERR_TX_DESERIALIZE); // Error deserializing
    }
}

unsigned int bitcoinconsensus_get_flags(const unsigned char* blockHeader, unsigned int blockHeaderLen, const Consensus::Params& consensusParams, void* pindexPrev, const Consensus::BlockIndexInterface& indexInterface, bitcoinconsensus_error* err)
{
    try {
        ObjectInputStream stream(SER_NETWORK, PROTOCOL_VERSION, blockHeader, blockHeaderLen);
        CBlockHeader header;
        stream >> header;
        if (header.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) != blockHeaderLen)
            return set_error(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);

        // Regardless of the verification result, the tx did not error.
        set_error(err, bitcoinconsensus_ERR_OK);

        const CBlockIndexView* pindex = new CBlockIndexCPPViewFromCInterface(indexInterface, pindexPrev);
        return GetConsensusFlags(header, consensusParams, pindex, false);
    } catch (const std::exception&) {
        return set_error(err, bitcoinconsensus_ERR_TX_DESERIALIZE); // Error deserializing
    }    
}

int bitcoinconsensus_verify_tx(const unsigned char* tx, unsigned int txLen, void* inputs, const Consensus::CoinsIndexInterface& inputsInterface, const int64_t nHeight, const int64_t nSpendHeight, const int64_t nLockTimeCutoff, unsigned int flags, int fScriptChecks, int cacheStore, uint64_t& nFees, int64_t& nSigOps, bitcoinconsensus_error* err)
{
    try {
        ObjectInputStream stream(SER_NETWORK, PROTOCOL_VERSION, tx, txLen);
        CTransaction tx;
        stream >> tx;
        if (tx.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) != txLen)
            return set_error(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);

        // Regardless of the verification result, the tx did not error.
        set_error(err, bitcoinconsensus_ERR_OK);

        CValidationState state;
        const CUtxoView* inputsView = new CUtxoViewFromCInterface(inputsInterface, inputs);
        CAmount& aFees = (CAmount&)nFees;
        return Consensus::VerifyTx(tx, state, *inputsView, nHeight, nSpendHeight, nLockTimeCutoff, flags, fScriptChecks, cacheStore, aFees, nSigOps);
    } catch (const std::exception&) {
        return set_error(err, bitcoinconsensus_ERR_TX_DESERIALIZE); // Error deserializing
    }
}

int bitcoinconsensus_verify_block(const unsigned char* block, unsigned int blockLen, const Consensus::Params& consensusParams, int64_t nTime, const int64_t nSpendHeight, void* pindexPrev, const Consensus::BlockIndexInterface& indexInterface, const void* inputs, const Consensus::CoinsIndexInterface& inputsInterface, bool fNewBlock, bool fScriptChecks, bool cacheStore, bool fCheckPOW, bitcoinconsensus_error* err)
{
    try {
        ObjectInputStream stream(SER_NETWORK, PROTOCOL_VERSION, block, blockLen);
        CBlock block;
        stream >> block;
        if (block.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) != blockLen)
            return set_error(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);

        // Regardless of the verification result, the tx did not error.
        set_error(err, bitcoinconsensus_ERR_OK);

        CValidationState state;
        const CBlockIndexView* pindex = new CBlockIndexCPPViewFromCInterface(indexInterface, pindexPrev);
        const CUtxoView* inputsView = new CUtxoViewFromCInterface(inputsInterface, inputs);
        return Consensus::VerifyBlock(block, state, consensusParams, nTime, nSpendHeight, pindex, *inputsView, false, fScriptChecks, cacheStore, fCheckPOW, true);
    } catch (const std::exception&) {
        return set_error(err, bitcoinconsensus_ERR_TX_DESERIALIZE); // Error deserializing
    }
}

unsigned int bitcoinconsensus_version()
{
    // Just use the API version for now
    return BITCOINCONSENSUS_API_VER;
}
