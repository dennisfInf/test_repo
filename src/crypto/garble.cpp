#include "emp-sh2pc/emp-sh2pc.h"
#include <cmath>
using namespace emp;
using namespace std;

void verify(int party, uint32_t share, Integer result)
{

    Integer share1(32, share, ALICE);
    Integer share2(32, share, BOB);
    Integer index = share1 ^ share2;
    if (!(index == result).reveal<bool>())
    {
        std::cout << "not verified " << std::endl;
        exit(1);
    }
    else
    {
        std::cout << "verified" << std::endl;
    }
}

uint32_t *add(int party, uint32_t share_pointer, uint32_t share_limit)
{
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
        exit(1);
    }

    Integer one = Integer(32, 1, 0);
    uint32_t *shares = new uint32_t[3];
    for (int i = 0; i < 3; i++)
    {
        cache = cache + one;
        cout
            << "cached val\t" << cache.reveal<uint32_t>() << endl;

        if (party == ALICE)
        {
            shares[i] = fmod(rand(), std::pow(2, 32));
            cout
                << "Add res\t" << shares[i] << endl;
        }
        Integer rand_a = Integer(32, shares[i], ALICE);
        shares_bob[i] = cache ^ rand_a;
        uint32_t bob_revealed_share = shares_bob[i].reveal<uint32_t>(BOB);
        if (party == BOB)
        {
            shares[i] = bob_revealed_share;
            cout
                << "Add res\t" << shares[i] << endl;
        }
        verify(party, shares[i], cache);
    }
    return shares;
}

int main(int argc, char **argv)
{
    int port, party;
    parse_party_and_port(argv, &party, &port);
    int num = 20;
    int num2 = 30;
    if (argc > 3)
        num = atoi(argv[3]);
    if (argc > 4)
        num2 = atoi(argv[4]);
    HighSpeedNetIO *io = new HighSpeedNetIO(party == ALICE ? nullptr : "127.0.0.1", port, port + 1);

    setup_semi_honest(io, party);

    uint32_t *shares = add(party, num, num2);
    // test_add(party, num);
    // test_millionare(party, num);
    //	test_sort(party);
    cout
        << CircuitExecution::circ_exec->num_and() << endl;
    finalize_semi_honest();
    delete io;
}
