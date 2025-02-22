#pragma once
#include <emp-tool/emp-tool.h>
#include "debug.h"
#include "sh_riro_garble.h"
#include <vector>
#include "utils_d.h"
#include <stack>

using namespace std;

namespace emp
{

    namespace optimalcht
    {
        using namespace thread_unsafe;

        // Set me in main!
        extern sh_riro::Circuit *lookup_circuit;

        extern double time_in_circuit, time_before_circuit, time_after_circuit;
        // some special values that fit into a uint
        // as signed ints, these are -1, -2, -3, etc
        extern const uint NONE;
        extern const uint ROOT;
        extern const uint UNVISITED;
        extern const uint STASHED;

        struct directed_edge
        {
            uint edge;
            uint vertex;
        };

        inline uint h0(const block *b, uint log_single_col_len)
        {
            const uint hash_mask = (1 << log_single_col_len) - 1;
            ull hi = ((ull *)b)[1];
            return hi & hash_mask;
        }

        inline uint h1(const block *b, uint log_single_col_len)
        {
            const uint hash_mask = (1 << log_single_col_len) - 1;
            ull hi = ((ull *)b)[1];
            return ((hi >> 32) & hash_mask) | (1 << log_single_col_len);
        }

        void build(vector<block> &table, uint log_single_col_len, const vector<block> &input_array, vector<uint> &stash_indices);

        uint lookup_from_2shares(block *table_2share, block key, uint log_single_col_len, rep_array_unsliced<uint> dummy_index, rep_array_unsliced<int> found, int builder);

    }

}
