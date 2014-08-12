// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script.h"

#include "script_interpreter.hpp"
#include "script_sign.hpp"
#include "script_standard.h"

#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha2.h"
#include "core.h"
#include "hash.h"
#include "key.h"
#include "keystore.h"
#include "random.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"

#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>

using namespace std;
using namespace boost;

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLDATA/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

bool IsCanonicalPubKey(const valtype &vchPubKey, unsigned int flags) {
    if (!(flags & SCRIPT_VERIFY_STRICTENC))
        return true;

    if (vchPubKey.size() < 33)
        return error("Non-canonical public key: too short");
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65)
            return error("Non-canonical public key: invalid length for uncompressed key");
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33)
            return error("Non-canonical public key: invalid length for compressed key");
    } else {
        return error("Non-canonical public key: compressed nor uncompressed");
    }
    return true;
}

bool IsCanonicalSignature(const valtype &vchSig, unsigned int flags) {
    if (!(flags & SCRIPT_VERIFY_STRICTENC))
        return true;

    // See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    // A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
    // Where R and S are not negative (their first byte has its highest bit not set), and not
    // excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    // in which case a single 0 byte is necessary and even required).
    if (vchSig.size() < 9)
        return error("Non-canonical signature: too short");
    if (vchSig.size() > 73)
        return error("Non-canonical signature: too long");
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return error("Non-canonical signature: unknown hashtype byte");
    if (vchSig[0] != 0x30)
        return error("Non-canonical signature: wrong type");
    if (vchSig[1] != vchSig.size()-3)
        return error("Non-canonical signature: wrong length marker");
    unsigned int nLenR = vchSig[3];
    if (5 + nLenR >= vchSig.size())
        return error("Non-canonical signature: S length misplaced");
    unsigned int nLenS = vchSig[5+nLenR];
    if ((unsigned long)(nLenR+nLenS+7) != vchSig.size())
        return error("Non-canonical signature: R+S length mismatch");

    const unsigned char *R = &vchSig[4];
    if (R[-2] != 0x02)
        return error("Non-canonical signature: R value type mismatch");
    if (nLenR == 0)
        return error("Non-canonical signature: R length is zero");
    if (R[0] & 0x80)
        return error("Non-canonical signature: R value negative");
    if (nLenR > 1 && (R[0] == 0x00) && !(R[1] & 0x80))
        return error("Non-canonical signature: R value excessively padded");

    const unsigned char *S = &vchSig[6+nLenR];
    if (S[-2] != 0x02)
        return error("Non-canonical signature: S value type mismatch");
    if (nLenS == 0)
        return error("Non-canonical signature: S length is zero");
    if (S[0] & 0x80)
        return error("Non-canonical signature: S value negative");
    if (nLenS > 1 && (S[0] == 0x00) && !(S[1] & 0x80))
        return error("Non-canonical signature: S value excessively padded");

    if (flags & SCRIPT_VERIFY_LOW_S) {
        // If the S value is above the order of the curve divided by two, its
        // complement modulo the order could have been used instead, which is
        // one byte shorter when encoded correctly.
        if (!CKey::CheckSignatureElement(S, nLenS, true))
            return error("Non-canonical signature: S value is unnecessarily high");
    }

    return true;
}

namespace {

/** Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction &txTo;  // reference to the spending transaction (the one being serialized)
    const CScript &scriptCode; // output script being consumed
    const unsigned int nIn;    // input index of txTo being signed
    const bool fAnyoneCanPay;  // whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    // whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      // whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s, int nType, int nVersion) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput, int nType, int nVersion) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout, nType, nVersion);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScript(), nType, nVersion);
        else
            SerializeScriptCode(s, nType, nVersion);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0, nType, nVersion);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence, nType, nVersion);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput, int nType, int nVersion) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut(), nType, nVersion);
        else
            ::Serialize(s, txTo.vout[nOutput], nType, nVersion);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s, int nType, int nVersion) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion, nType, nVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput, nType, nVersion);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput, nType, nVersion);
        // Serialie nLockTime
        ::Serialize(s, txTo.nLockTime, nType, nVersion);
    }
};

} // anon namespace

class CScriptTx {
private:
    const CTransaction txTo;  // reference to the spending transaction (the one being serialized)
    const unsigned int nIn;    // input index of txTo being signed
public:
    CScriptTx(const CTransaction& txToIn, unsigned int nInIn) :
        txTo(txToIn), nIn(nInIn) {}

    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const;
};

uint256 CScriptTx::SignatureHash(const CScript& scriptCode, int nHashType) const
{
    if (nIn >= txTo.vin.size()) {
        LogPrintf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            LogPrintf("ERROR: SignatureHash() : nOut=%d out of range\n", nIn);
            return 1;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    CScriptTx tx(txTo, nIn);
    return tx.SignatureHash(scriptCode, nHashType);
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    CScriptTx tx(txTo, nIn);
    return EvalScript(stack, script, tx, flags, nHashType);
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    CScriptTx tx(txTo, nIn);
    return VerifyScript(scriptSig, scriptPubKey, tx, flags, nHashType);
}

bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    CScriptTx tx(txTo, nIn);
    return SignSignature(keystore, fromPubKey, tx, nHashType, txin.scriptSig);
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    CScriptTx tx(txTo, nIn);
    return SignSignature(keystore, txout.scriptPubKey, tx, nHashType, txin.scriptSig);
}

CScript CombineSignatures(CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn, const CScript& scriptSig1, const CScript& scriptSig2)
{
    CScriptTx tx(txTo, nIn);
    CTransaction txAux;
    CScriptTx emptyTx(txAux, 0);
    return CombineSignatures(scriptPubKey, tx, emptyTx, scriptSig1, scriptSig2);
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

bool CScript::IsPushOnly() const
{
    const_iterator pc = begin();
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::HasCanonicalPushes() const
{
    const_iterator pc = begin();
    while (pc < end())
    {
        opcodetype opcode;
        std::vector<unsigned char> data;
        if (!GetOp(pc, opcode, data))
            return false;
        if (opcode > OP_16)
            continue;
        if (opcode < OP_PUSHDATA1 && opcode > OP_0 && (data.size() == 1 && data[0] <= 16))
            // Could have used an OP_n code, rather than a 1-byte push.
            return false;
        if (opcode == OP_PUSHDATA1 && data.size() < OP_PUSHDATA1)
            // Could have used a normal n-byte push, rather than OP_PUSHDATA1.
            return false;
        if (opcode == OP_PUSHDATA2 && data.size() <= 0xFF)
            // Could have used an OP_PUSHDATA1.
            return false;
        if (opcode == OP_PUSHDATA4 && data.size() <= 0xFFFF)
            // Could have used an OP_PUSHDATA2.
            return false;
    }
    return true;
}

class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << scriptID << OP_EQUAL;
        return true;
    }
};

void CScript::SetDestination(const CTxDestination& dest)
{
    boost::apply_visitor(CScriptVisitor(this), dest);
}

void CScript::SetMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    this->clear();

    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const CPubKey& key, keys)
        *this << key;
    *this << EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
}

bool CScriptCompressor::IsToKeyID(CKeyID &hash) const
{
    if (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160
                            && script[2] == 20 && script[23] == OP_EQUALVERIFY
                            && script[24] == OP_CHECKSIG) {
        memcpy(&hash, &script[3], 20);
        return true;
    }
    return false;
}

bool CScriptCompressor::IsToScriptID(CScriptID &hash) const
{
    if (script.size() == 23 && script[0] == OP_HASH160 && script[1] == 20
                            && script[22] == OP_EQUAL) {
        memcpy(&hash, &script[2], 20);
        return true;
    }
    return false;
}

bool CScriptCompressor::IsToPubKey(CPubKey &pubkey) const
{
    if (script.size() == 35 && script[0] == 33 && script[34] == OP_CHECKSIG
                            && (script[1] == 0x02 || script[1] == 0x03)) {
        pubkey.Set(&script[1], &script[34]);
        return true;
    }
    if (script.size() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG
                            && script[1] == 0x04) {
        pubkey.Set(&script[1], &script[66]);
        return pubkey.IsFullyValid(); // if not fully valid, a case that would not be compressible
    }
    return false;
}

bool CScriptCompressor::Compress(std::vector<unsigned char> &out) const
{
    CKeyID keyID;
    if (IsToKeyID(keyID)) {
        out.resize(21);
        out[0] = 0x00;
        memcpy(&out[1], &keyID, 20);
        return true;
    }
    CScriptID scriptID;
    if (IsToScriptID(scriptID)) {
        out.resize(21);
        out[0] = 0x01;
        memcpy(&out[1], &scriptID, 20);
        return true;
    }
    CPubKey pubkey;
    if (IsToPubKey(pubkey)) {
        out.resize(33);
        memcpy(&out[1], &pubkey[1], 32);
        if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
            out[0] = pubkey[0];
            return true;
        } else if (pubkey[0] == 0x04) {
            out[0] = 0x04 | (pubkey[64] & 0x01);
            return true;
        }
    }
    return false;
}

unsigned int CScriptCompressor::GetSpecialSize(unsigned int nSize) const
{
    if (nSize == 0 || nSize == 1)
        return 20;
    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5)
        return 32;
    return 0;
}

bool CScriptCompressor::Decompress(unsigned int nSize, const std::vector<unsigned char> &in)
{
    switch(nSize) {
    case 0x00:
        script.resize(25);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;
        memcpy(&script[3], &in[0], 20);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;
        return true;
    case 0x01:
        script.resize(23);
        script[0] = OP_HASH160;
        script[1] = 20;
        memcpy(&script[2], &in[0], 20);
        script[22] = OP_EQUAL;
        return true;
    case 0x02:
    case 0x03:
        script.resize(35);
        script[0] = 33;
        script[1] = nSize;
        memcpy(&script[2], &in[0], 32);
        script[34] = OP_CHECKSIG;
        return true;
    case 0x04:
    case 0x05:
        unsigned char vch[33] = {};
        vch[0] = nSize - 2;
        memcpy(&vch[1], &in[0], 32);
        CPubKey pubkey(&vch[0], &vch[33]);
        if (!pubkey.Decompress())
            return false;
        assert(pubkey.size() == 65);
        script.resize(67);
        script[0] = 65;
        memcpy(&script[1], pubkey.begin(), 65);
        script[66] = OP_CHECKSIG;
        return true;
    }
    return false;
}
