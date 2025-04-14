#include "32bitadd_circuit.h"
using namespace emp;
using namespace std;

namespace gc
{
    uint32_t *add(const int party, HighSpeedNetIO *io, uint32_t share_pointer, uint32_t share_limit)
    {
        setup_semi_honest(io, party);

        Integer share_p1(32, share_pointer, ALICE);
        Integer share_p2(32, share_pointer, BOB);
        Integer *shares_bob = new Integer[3];
        Integer cache = share_p1 ^ share_p2;
        Integer share_l1(32, share_limit, ALICE);
        Integer share_l2(32, share_limit, BOB);
        Integer limit = share_l1 ^ share_l2;
        if ((limit == cache).reveal<bool>())
        {
            std::cout << "limit of loogbook entries reached" << std::endl;
            finalize_semi_honest();
            exit(1);
        }

        Integer one = Integer(32, 1, 0);
        uint32_t *shares = new uint32_t[3];
        for (int i = 0; i < 3; i++)
        {
            cache = cache + one;
            if (party == ALICE)
            {
                shares[i] = fmod(rand(), std::pow(2, 32));
            }
            Integer rand_a = Integer(32, shares[i], ALICE);
            shares_bob[i] = cache ^ rand_a;
            uint32_t bob_revealed_share = shares_bob[i].reveal<uint32_t>(BOB);

            if (party == BOB)
            {
                shares[i] = bob_revealed_share;
            }
        }
        finalize_semi_honest();
        return shares;
    }

};