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
            ( 57484, uint256("0x807fb268c7faabc70cc95c1027cbf1e555834e5bf9e19e01ef785be88853ae88"))
            ( 69240, uint256("0x07d2b42e1898d59594b10f26fdc76d4f970a10b4b330237012f48eb489c8d744"))
            ( 73892, uint256("0x5b43092ef40969b65878cee7c568e622a4a9d950a130858a10914402797f96b1"))
            ;


    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet) return true; // Testnet has no checkpoints

        MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
        if (i == mapCheckpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet) return 0;
        return mapCheckpoints.rbegin()->first;
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
        }
        return NULL;
    }

    uint256 GetLatestHardenedCheckpoint()
    {
        const MapCheckpoints& checkpoints = mapCheckpoints;
        return (checkpoints.rbegin()->second);
    }
}
