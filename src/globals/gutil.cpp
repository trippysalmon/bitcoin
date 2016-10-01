// Copyright (c) 2016-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gutil.h"

#include "util.h"

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    return GetArg(strArg, nDefault, mapArgs);
}
