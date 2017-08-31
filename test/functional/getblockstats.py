#!/usr/bin/env python3
# Copyright (c) 2017-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    connect_nodes_bi,
)

class GetblockstatsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.is_network_split = False
        self.num_nodes = 2
        self.extra_args = [
            ['-debug', '-txindex', '-whitelist=127.0.0.1'],
            ['-debug', '-txindex', '-whitelist=127.0.0.1', '-paytxfee=0.003'],
        ]

    def setup_network(self):
        self.nodes = self.start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args)
        connect_nodes_bi(self.nodes, 0 , 1)
        self.sync_all()

    def assert_contains(self, data, values, check_cointains=True):
        for val in values:
            if (check_cointains):
                assert(val in data)
            else:
                assert(val not in data)

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)

        node.sendtoaddress(address=self.nodes[1].getnewaddress(), amount=10, subtractfeefromamount=True)
        node.generate(1)
        self.sync_all()

        node.sendtoaddress(address=node.getnewaddress(), amount=10, subtractfeefromamount=True)
        node.sendtoaddress(address=node.getnewaddress(), amount=10, subtractfeefromamount=True)
        self.nodes[1].sendtoaddress(address=node.getnewaddress(), amount=1, subtractfeefromamount=True)
        self.sync_all()
        node.generate(1)

        start_height = 101
        max_stat_pos = 2
        stats = node.getblockstats(start=start_height, end=start_height + max_stat_pos)

        all_values = [
            "height",
            "time",
            "mediantime",
            "txs",
            "swtxs",
            "ins",
            "outs",
            "subsidy",
            "totalfee",
            "reward",
            "utxo_increase",
            "utxo_size_inc",
            "total_size",
            "total_weight",
            "swtotal_size",
            "swtotal_weight",
            "total_out",
            "minfee",
            "maxfee",
            "medianfee",
            "avgfee",
            "minfeerate",
            "maxfeerate",
            "medianfeerate",
            "avgfeerate",
            "minfeerate_old",
            "maxfeerate_old",
            "medianfeerate_old",
            "avgfeerate_old",
        ]
        self.assert_contains(stats, all_values)
        # Make sure all valid statistics are included
        self.assert_contains(all_values, stats.keys())

        assert_equal(stats['height'][0], start_height)
        assert_equal(stats['height'][max_stat_pos], start_height + max_stat_pos)

        assert_equal(stats['txs'][0], 1)
        assert_equal(stats['swtxs'][0], 0)
        assert_equal(stats['ins'][0], 0)
        assert_equal(stats['outs'][0], 2)
        assert_equal(stats['totalfee'][0], 0)
        assert_equal(stats['utxo_increase'][0], 2)
        assert_equal(stats['utxo_size_inc'][0], 173)
        assert_equal(stats['total_size'][0], 0)
        assert_equal(stats['total_weight'][0], 0)
        assert_equal(stats['swtotal_size'][0], 0)
        assert_equal(stats['swtotal_weight'][0], 0)
        assert_equal(stats['total_out'][0], 0)
        assert_equal(stats['minfee'][0], 0)
        assert_equal(stats['maxfee'][0], 0)
        assert_equal(stats['medianfee'][0], 0)
        assert_equal(stats['avgfee'][0], 0)
        assert_equal(stats['minfeerate'][0], 0)
        assert_equal(stats['maxfeerate'][0], 0)
        assert_equal(stats['medianfeerate'][0], 0)
        assert_equal(stats['avgfeerate'][0], 0)
        assert_equal(stats['minfeerate_old'][0], 0)
        assert_equal(stats['maxfeerate_old'][0], 0)
        assert_equal(stats['medianfeerate_old'][0], 0)
        assert_equal(stats['avgfeerate_old'][0], 0)

        assert_equal(stats['txs'][1], 2)
        assert_equal(stats['swtxs'][1], 0)
        assert_equal(stats['ins'][1], 1)
        assert_equal(stats['outs'][1], 4)
        assert_equal(stats['totalfee'][1], 3840)
        assert_equal(stats['utxo_increase'][1], 3)
        assert_equal(stats['utxo_size_inc'][1], 238)
        # assert_equal(stats['total_size'][1], 191)
        # assert_equal(stats['total_weight'][1], 768)
        assert_equal(stats['total_out'][1], 4999996160)
        assert_equal(stats['minfee'][1], 3840)
        assert_equal(stats['maxfee'][1], 3840)
        assert_equal(stats['medianfee'][1], 3840)
        assert_equal(stats['avgfee'][1], 3840)
        assert_equal(stats['minfeerate'][1], 20)
        assert_equal(stats['maxfeerate'][1], 20)
        assert_equal(stats['medianfeerate'][1], 20)
        assert_equal(stats['avgfeerate'][1], 20)
        assert_equal(stats['minfeerate_old'][1], 20)
        assert_equal(stats['maxfeerate_old'][1], 20)
        assert_equal(stats['medianfeerate_old'][1], 20)
        assert_equal(stats['avgfeerate_old'][1], 20)

        assert_equal(stats['txs'][max_stat_pos], 4)
        assert_equal(stats['swtxs'][max_stat_pos], 0)
        assert_equal(stats['ins'][max_stat_pos], 3)
        assert_equal(stats['outs'][max_stat_pos], 8)
        assert_equal(stats['totalfee'][max_stat_pos], 76160)
        assert_equal(stats['utxo_increase'][max_stat_pos], 5)
        assert_equal(stats['utxo_size_inc'][max_stat_pos], 388)
        # assert_equal(stats['total_size'][max_stat_pos], 643)
        # assert_equal(stats['total_weight'][max_stat_pos], 2572)
        assert_equal(stats['total_out'][max_stat_pos], 9999920000)
        assert_equal(stats['minfee'][max_stat_pos], 3840)
        assert_equal(stats['maxfee'][max_stat_pos], 67800)
        assert_equal(stats['medianfee'][max_stat_pos], 4520)
        assert_equal(stats['avgfee'][max_stat_pos], 25386)
        assert_equal(stats['minfeerate'][max_stat_pos], 20)
        # assert_equal(stats['maxfeerate'][max_stat_pos], 300)
        assert_equal(stats['medianfeerate'][max_stat_pos], 20)
        assert_equal(stats['avgfeerate'][max_stat_pos], 118)
        assert_equal(stats['minfeerate_old'][max_stat_pos], 20)
        # assert_equal(stats['maxfeerate_old'][max_stat_pos], 301)
        assert_equal(stats['medianfeerate_old'][max_stat_pos], 20)
        assert_equal(stats['avgfeerate_old'][max_stat_pos], 118)

        # Testing reward is redundant, can be calculated in the plotter client
        subsidy = 5000000000
        assert_equal(stats['reward'][0], subsidy + stats['totalfee'][0])
        assert_equal(stats['reward'][1], subsidy + stats['totalfee'][1])
        assert_equal(stats['reward'][max_stat_pos], subsidy + stats['totalfee'][max_stat_pos])

        # Test invalid parameters raise the proper json exceptions
        tip = start_height + max_stat_pos 
        assert_raises_jsonrpc(-8, 'Start block height %d after current tip %d' % (tip+1, tip), node.getblockstats, start=tip+1)
        assert_raises_jsonrpc(-8, 'Start block height %d after current tip %d' % (-1, tip), node.getblockstats, start=-tip-1)
        assert_raises_jsonrpc(-8, 'Start block height %d higher than end %d' % (tip-1, tip-2), node.getblockstats, start=-1, end=-2)
        assert_raises_jsonrpc(-8, 'End block height %d after current tip %d' % (tip+1, tip), node.getblockstats, start=1, end=tip+1)
        assert_raises_jsonrpc(-8, 'Start block height 2 higher than end 1', node.getblockstats, start=2, end=1)
        assert_raises_jsonrpc(-8, 'Start block height %d higher than end %d' % (tip, tip-1), node.getblockstats, start=tip, end=tip-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            'minfee,%s' % inv_sel_stat,
            '%s,minfee' % inv_sel_stat,
            'minfee,%s,maxfee' % inv_sel_stat,
        ]
        for inv_stat in inv_stats:
            assert_raises_jsonrpc(-8, 'Invalid selected statistic %s' % inv_sel_stat, node.getblockstats, start=1, end=2, stats=inv_stat)
        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_jsonrpc(-8, 'Invalid selected statistic aaa%s' % inv_sel_stat, node.getblockstats, start=1, end=2, stats='minfee,aaa%s' % inv_sel_stat)

        # Make sure only the selected statistics are included
        stats = node.getblockstats(start=1, end=2, stats='minfee,maxfee')
        some_values = [
            'minfee',
            'maxfee',
        ]
        self.assert_contains(stats, some_values)
        # Make sure valid stats that haven't been selected don't appear
        other_values = [x for x in all_values if x not in some_values]
        self.assert_contains(stats, other_values, False)

if __name__ == '__main__':
    GetblockstatsTest().main()
