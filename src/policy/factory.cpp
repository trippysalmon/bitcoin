// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "policy/interface.h" // This implements functions declared in policy/interface.h

#include "policy/policy.h"
#include "util.h"
#include "tinyformat.h"

/** Policy Factory and related utility functions */

void Policy::AppendHelpMessages(std::string& strUsage)
{
    const CStandardPolicy policy;
    strUsage += HelpMessageGroup(strprintf(_("Policy options: (for policy: %s)"), Policy::STANDARD));
    AppendMessagesOpt(strUsage, policy.GetOptionsHelp());
}
