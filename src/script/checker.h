// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_CHECKER
#define H_BITCOIN_SCRIPT_CHECKER

#include <vector>

class CPubKey;
class CScript;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

class SignatureHasher
{
public:
    virtual uint256 SignatureHash(const CScript& scriptCode, int nHashType) const = 0;
};

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class SignatureChecker : public BaseSignatureChecker
{
private:
    const SignatureHasher& hasher;
protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    SignatureChecker(const SignatureHasher& hasherIn) : hasher(hasherIn) { }
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const;
};

#endif // H_BITCOIN_SCRIPT_CHECKER
