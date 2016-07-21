// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_FLAGS_H
#define BITCOIN_CONSENSUS_FLAGS_H

/** 
 * Script verification flags.
 * @TODO: decouple bit numbers from script flags.
 */
enum
{
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), // enable CHECKSEQUENCEVERIFY (BIP112)
    bitcoinconsensus_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), // enable WITNESS (BIP141)

    /* BIP34: Verify coinbase transactions commit to the current height. */
    bitcoinconsensus_TX_COINBASE_VERIFY_BIP34 = (1U << 13),

    /* BIP30: See Consensus::GetFlags(), Consensus::VerifyTx() and http://r6.ca/blog/20120206T005236Z.html for more information */
    bitcoinconsensus_TX_VERIFY_BIP30 = (1U << 14),

    /* BIP113: Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1U << 15),

    /* BIP68: Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 16),
};

#endif // BITCOIN_CONSENSUS_FLAGS_H
