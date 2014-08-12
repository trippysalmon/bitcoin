
#include "script_sign.hpp"

class Signable {
public:
    Signable() {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const { return 1; }
};

bool CompileSignSignature(const CKeyStore& keystore, const CScript& fromPubKey, int nHashType)
{
    CScript scriptSig;
    Signable tx;
    return SignSignature(keystore, fromPubKey, tx, nHashType, scriptSig);
}

CScript CompileCombineSignatures(CScript scriptPubKey, const CScript& scriptSig1, const CScript& scriptSig2)
{
    Signable tx;
    return CombineSignatures(scriptPubKey, tx, tx, scriptSig1, scriptSig2);
}
