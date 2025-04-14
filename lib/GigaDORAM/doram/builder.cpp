#include "builder.h"
namespace emp
{
    void initialize_resource_set(int resource_id, string prev_host, string next_host, int prev_port, int next_port)
    {
        dbg_args(resource_id, prev_port, next_port);
        if (party == 1)
        {
            next_ios[resource_id] = new RepNetIO(nullptr, next_port, true);
            prev_ios[resource_id] = new RepNetIO(nullptr, prev_port, true);
        }
        else if (party == 2)
        {
            prev_ios[resource_id] = new RepNetIO(prev_host.c_str(), prev_port, true);
            next_ios[resource_id] = new RepNetIO(nullptr, next_port, true);
        }
        else
        {
            next_ios[resource_id] = new RepNetIO(next_host.c_str(), next_port, true);
            prev_ios[resource_id] = new RepNetIO(prev_host.c_str(), prev_port, true);
        }
        next_prgs[resource_id] = new PRG();
        next_ios[resource_id]->send_block(&next_prgs[resource_id]->key, 1);
        next_ios[resource_id]->flush();

        block prev_prg_key;
        prev_ios[resource_id]->recv_block(&prev_prg_key, 1);
        prev_prgs[resource_id] = new PRG(&prev_prg_key);
        private_prgs[resource_id] = new PRG();
        shared_prgs[resource_id] = new PRG(&all_one_block);
        rep_execs[resource_id] = new SHRepArray(resource_id);
    }

    void initialize_all_resources(string prev_host, string next_host, int prev_port, int next_port)
    {
        prev_prgs = new PRG *[NUM_THREADS];
        next_prgs = new PRG *[NUM_THREADS];
        private_prgs = new PRG *[NUM_THREADS];
        shared_prgs = new PRG *[NUM_THREADS];

        prev_ios = new RepNetIO *[NUM_THREADS];
        next_ios = new RepNetIO *[NUM_THREADS];
        rep_execs = new SHRepArray *[NUM_THREADS];

        for (uint resource_id = 0; resource_id < NUM_THREADS; resource_id++)
        {
            initialize_resource_set(resource_id, prev_host, next_host, prev_port + resource_id, next_port + resource_id);
        }

        {
            using namespace thread_unsafe;
            prev_prg = prev_prgs[0];
            next_prg = next_prgs[0];
            private_prg = private_prgs[0];
            shared_prg = shared_prgs[0];
            prev_io = prev_ios[0];
            next_io = next_ios[0];
            rep_exec = rep_execs[0];
        }
    }

    rep_array_unsliced<y_type> *init(int party_index, string prev_host_and_port, string next_host_and_port, bool BUILD_BOTTOM_LEVEL_AT_STARTUP, uint LOG_ADDRESS_SPACE, uint NUM_LEVELS, uint LOG_AMP_FACTOR, int NUM_THREADS)
    {
        // this is a global because of the inclusion of debug

        party = party_index;
        string circuits_dir = "/app/lib/GigaDORAM/circuits";

        //! Named Parameters!
        string PRF_CIRCUIT_FILENAME = "LowMC_reuse_wires.txt";

        uint N = 1 << LOG_ADDRESS_SPACE;
        string prf_circ_filename = circuits_dir + "/" + PRF_CIRCUIT_FILENAME;
        string cht_circ_filename = circuits_dir + "/cht_lookup.txt";
        string stupid_level_circ_filename = circuits_dir + "/xy_if_xs_equal.txt";
        string compare_swap_circuit_filename = circuits_dir + "/compare_swap.txt";
        string dummy_check_dir = circuits_dir + "/dummy_check";
        string replace_if_dummy_dir = circuits_dir + "/replace_if_dummy";
        std::cout << "parsing circuits" << std::endl;

        prf_circuit =
            new BristolFashion_array(prf_circ_filename); // make in main since we will use both for query and build
        cht_lookup_circuit_file = new BristolFashion_array(cht_circ_filename);
        xy_if_xs_equal_circuit = new BristolFashion_array(stupid_level_circ_filename);
        compare_swap_circuit_file = new BristolFashion_array(compare_swap_circuit_filename);
        for (uint log_N = 6; log_N <= 31; log_N++)
        {
            dummy_check_circuit_file[log_N] = new BristolFashion_array(dummy_check_dir + "/" + to_string(log_N) + ".txt");
            replace_if_dummy_circuit_file[log_N] =
                new BristolFashion_array(replace_if_dummy_dir + "/" + to_string(log_N) + ".txt");
        }
        std::cout << "parsing ports" << std::endl;
        string prev_host, next_host;
        uint prev_port = 0, next_port = 0;
        parse_host_and_port(prev_host_and_port, prev_host, prev_port);
        parse_host_and_port(next_host_and_port, next_host, next_port);
        std::cout << "prev_port: " << prev_port << "prev host:" << prev_host << std::endl;
        std::cout << "next_port: " << next_port << "next_host: " << next_host << std::endl;
        initialize_all_resources(prev_host, next_host, prev_port, next_port);
        using namespace thread_unsafe;
        optimalcht::lookup_circuit = new sh_riro::Circuit(*cht_lookup_circuit_file);

        dbg("got to input setup");
        dbg_args(prf_key_size_blocks());

        //* setup inputs, in this case a list [(X, Y) to secret share], currently using 0,...,N-1, both are 64 bit values
        //! remember, N is also reserved!
        rep_array_unsliced<y_type> *ys = nullptr;
        if (BUILD_BOTTOM_LEVEL_AT_STARTUP)
        {
            ys = new rep_array_unsliced<y_type>(N - 1);
            {
                vector<y_type> _ys_clear(N - 1);
                for (uint i = 0; i < N - 1; i++)
                {
                    _ys_clear[i] = i + 1;
                }
                ys->input_public(_ys_clear.data());
            }
        }
        return ys;
    }
}