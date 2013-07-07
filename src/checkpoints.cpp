// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2013 Luckycoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //

	// no checkpoint now, can be added in later releases
    static MapCheckpoints mapCheckpoints =
            boost::assign::map_list_of
            (     1, uint256("0xcf2f78756f0fa64bc4ce80e6d500661cc4c20f2be28c7d859467dceb0adfa2de"))
            (    53, uint256("0x9343eae8db94d5d5e945b0c0a6b83647b6a3a8fd89cd170a757e06dcbf2e3bed"))
            (   117, uint256("0x5208d62f44467e800a92bfb18fc0fd4c39d9fed28f4ad160262f96dd90111ec3"))
            (   200, uint256("0xa5ce00c4aab4f9deccbef0af27adadb29cbf111eb442e92895d7302eb047ad4e"))
            (  6452, uint256("0xe502fdfb3a35ee853ccd4a68433b1f9bbe3295c7d453fbcc484d06a766971475"))
            ( 10978, uint256("0x88fcee5009a0febf7832750d0246bf4a9b88f8195befc795e5f34b0d1e0e92f9"))
            ( 17954, uint256("0x7d40a9b80dd1b585b36e092aefcd3e579ef38f3180ea55dac53ead486f5d9cd2"))
            ( 23978, uint256("0x6f111b6eef7dccc2da3c85014964aa402f39c684ba5709b576777503c87141af"))
            ( 33212, uint256("0xe3b53359c1b088ec1f772d53eaa765d5c7410f0d9914e69bdb2a0fc881ddc9e8"))
            ( 45527, uint256("0x41849cf3bd7b819a6a994d17dcfb1cbc7eadfe63fa61cc1411cfe42177abc06a"))
			;
        /*
        boost::assign::map_list_of
        (     1, uint256("0x000000552acd41b1f9ae21fc7eb4054dce1331c8755f37f3d30a15825f695cd4"))
        (     2, uint256("0x000008559730ac71244fcca965c73077616a3cebff5e28dadeb61e8ddae631ae"))
        (  1500, uint256("0x841a2965955dd288cfa707a755d05a54e45f8bd476835ec9af4402a2b59a2967"))
        (  4032, uint256("0x9ce90e427198fc0ef05e5905ce3503725b80e26afd35a987965fd7e3d9cf0846"))
        (  8064, uint256("0xeb984353fc5190f210651f150c40b8a4bab9eeeff0b729fcb3987da694430d70"))
        ( 16128, uint256("0x602edf1859b7f9a6af809f1d9b0e6cb66fdc1d4d9dcd7a4bec03e12a1ccd153d"))
        ( 23420, uint256("0xd80fdf9ca81afd0bd2b2a90ac3a9fe547da58f2530ec874e978fce0b5101b507"))
        ( 50000, uint256("0x69dc37eb029b68f075a5012dcc0419c127672adb4f3a32882b2b3e71d07a20a6"))
        ( 80000, uint256("0x4fcb7c02f676a300503f49c764a89955a8f920b46a8cbecb4867182ecdb2e90a"))
        (120000, uint256("0xbd9d26924f05f6daa7f0155f32828ec89e8e29cee9e7121b026a7a3552ac6131"))
        (161500, uint256("0xdbe89880474f4bb4f75c227c77ba1cdc024991123b28b8418dbbf7798471ff43"))
        (179620, uint256("0x2ad9c65c990ac00426d18e446e0fd7be2ffa69e9a7dcb28358a50b2b78b9f709"))
        ;
        */

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet) return true; // Testnet has no checkpoints

        MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
        if (i == mapCheckpoints.end()) return true;
        return hash == i->second;
		// return true;
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet) return 0;
	
        return mapCheckpoints.rbegin()->first;
		// return 0;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (fTestNet) return NULL;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
				// return NULL;
        }
        return NULL;
    }
}
