#!/usr/bin/env python3
# Copyright (c) 2016-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test -reindex and -reindex-chainstate with CheckBlockIndex for -chain=custom
#
from reindex import ReindexTest

if __name__ == '__main__':
    ReindexTest("custom").main()
