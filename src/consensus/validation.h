// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VALIDATION_H
#define BITCOIN_CONSENSUS_VALIDATION_H

#include <string>

/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
static const unsigned char REJECT_DUST = 0x41;
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

class ValidationResult
{
public:
    const int nDoS;
    const bool fValid;
    const std::string error;
    const unsigned char rejectCode;
    const std::string reason;
    const bool fCorruption;

    ValidationResult(const int nDoSIn, const bool fValidIn = false, const std::string& errorIn="",
             const unsigned char rejectCodeIn=0, const std::string& reasonIn="",
             const bool fCorruptionIn=false)
        : nDoS(nDoSIn), fValid(fValidIn), error(errorIn), rejectCode(rejectCodeIn), reason(reasonIn), fCorruption(fCorruptionIn) {}
};

#endif // BITCOIN_CONSENSUS_VALIDATION_H
