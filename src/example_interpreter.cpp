
#include "script_interpreter.hpp"

class Signable {
public:
    Signable() {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const { return 1; }
};

bool CompileCheckSig(vector<unsigned char> vchSig, const vector<unsigned char>& vchPubKey, const CScript& scriptCode, int nHashType, int flags)
{
    return CheckSig(vchSig, vchPubKey, scriptCode, Signable(), nHashType, flags);
}

bool CompileEvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, int nHashType)
{
    return EvalScript(stack, script, Signable(), flags, nHashType);
}

bool CompileVerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, int nHashType)
{
    return VerifyScript(scriptSig, scriptPubKey, Signable(), flags, nHashType);
}
