#pragma once

#include "bit_manip_utils.h"
#include "emp-tool/emp-tool.h"
#include "globals.h"
// #include <string.h>
#include <fstream>
#include <sys/socket.h>

#define write_time(time_var) timing_file << #time_var << ": " << time_var << endl;
#define write_info(info) timing_file << "{ " << info << " }" << endl;
#define write_time_info(time_var, info) timing_file << #time_var << ", {" << (info) << "} : " << time_var << endl;
#define write_time_info_rel_tot(time_var, info, rel_to)                                        \
    timing_file << #time_var << ", {" << (info) << "} : " << time_var << " which made up for " \
                << 100 * (double)time_var / rel_to << "\% of " << #rel_to << endl;

namespace emp
{

    //[from, to) how it works: shift from to be 0 by subtructing from to, then we have that our range fits in UINT_MAX
    // UINT_MAX//(to-from) times. we poll a random number, if it is within the fitting blocks, take the mod of where it is
    // in it's block, else repoll
    // * sample random integer in [from, to)
    unsigned long long sample_unif_from_prg(PRG *prg, unsigned long long from, unsigned long long to);

    //! do we use this anymore? mayeb delete?
    template <typename T>
    block local_shuffle(PRG *prg, T *list, u_int list_len);

    extern int next_party(int wrt = party);

    extern int prev_party(int wrt = party);

    void init_timing_file();

    void parse_host_and_port(string host_and_port, string &host, uint &port);
    //void send_data(string data);
} // namespace emp
