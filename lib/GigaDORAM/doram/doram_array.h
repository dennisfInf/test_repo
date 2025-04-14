#pragma once

// typedef ull when we use it for y_type
#include "debug.h"
#include "globals.h" //player's global prgs&ios
#include "ohtable_array.h"
#include "stupid_level.h"
#include "batcher.h"

#include <fstream>     //log
#include <sys/types.h> // uint

// #define q_type block;

// Hack for testing: made these editable
// TODO: proper DORAM config files
extern uint STASH_SIZE_USE_EMPIRICAL_CHT_BOUNDS;
extern uint STASH_SIZE_USE_PROVEN_CHT_BOUNDS;

extern const bool use_proven_cht_bounds;

namespace emp
{
    class DORAM
    {
    public:
        // constructor inits these
        uint log_address_space_size;
        uint num_levels;
        uint log_amp_factor;
        rep_array_unsliced<block> prf_keys;

        uint log_sls, stupid_fill_time, stash_size; // params set by testing
        uint amp_factor;

        double d; // ratio of CHT_col_len/actual_data_len

        // prf stuff

        //* ohtable levels are 0-indexed:
        //* first level after stupid level is 0
        //* bottom level is num_levels - 1
        vector<OHTable_array *> ohtables;
        StupidLevel *stupid_level;

        //?all the other ohtable params: make a struct?
        vector<uint> base_b_state_vec;

        // to log
        fstream logger;

        bool had_initial_bottom_level;

    public:
        DORAM(uint log_address_space_size, rep_array_unsliced<y_type> *ys_no_dummy_room, uint num_levels, uint log_amp_factor);
        uint get_num_alive_levels();
        uint total_num_els_and_dummies(uint level_num, uint state_override = UINT_MAX);

    private:
        void decide_params();

        void init_logger();

        void logger_write(string msg);

        //*xs and ys must have len data_len+get_num_dummies(data_len)
        // base b should be incremmented on the outside
        void new_ohtable_of_level(uint level_num, rep_array_unsliced<x_type> xs, rep_array_unsliced<y_type> ys);

        void delete_ohtable(uint lvl);

        rep_array_unsliced<block> generate_prf_key(uint level_num);

        // we err on the larget side of things, hence the +1 for possible round-downs
        uint get_log_col_len(uint level_num, uint _state = UINT_MAX);

        uint get_num_dummies(uint level_num); // B^i * stupid_level_size (not including stash size )

        uint num_elements_at(uint level_num, uint state_override = UINT_MAX); //*this depends on the state vector

    public:
        uint get_num_levels()
        {
            return num_levels;
        } // we need this for alibi testing

        bool __all_tests_have_passed = false;
        // for now do a soft initialize which calls another function, perhaps we would want to do an
        // incremental intialize
        //? note that xs and ys need be deallocated by caller? (that's the way it is, is it a good practice?, it's
        // different
        // than @ ohtable)
        ~DORAM();

        rep_array_unsliced<y_type> read_and_write(rep_array_unsliced<x_type> qry_x, rep_array_unsliced<y_type> qry_y,
                                                  rep_array_unsliced<int> is_write);

        void rebuild();

        void cleanse_bottom_level(rep_array_unsliced<x_type> extracted_list_xs,
                                  rep_array_unsliced<y_type> extracted_list_ys,
                                  rep_array_unsliced<x_type> cleansed_for_bottom_level_xs,
                                  rep_array_unsliced<y_type> cleansed_for_bottom_level_ys,
                                  uint log_N);

        // overwrites extracted_list_xs
        static void relabel_dummies(rep_array_unsliced<x_type> extracted_list_xs, uint log_N);

        // runs a test on rebuilding
        //? maybe I do want some params in...
        /*
            the workings of doram are so intertwined that I think pretty much no matter what I do, if I don't basically
           run DORAM, then I wouldn't be able to test it properly. For example, here, I populated a number of levels and
           fake queried them w/o reinserting and while keeping track of what I queried, and in the end (also checking
           stashes) I made sure everything made it to the rebuild_to level. Still, w/o reinsetion, the data counts would
           be wrong for the rebuild-- eh maybe not? no I think this can still work..lets try more
        */

        void insert_stash(uint level_num);

        // clears teh heirchical structure and 0's the state
        void clear_doram();

        void extract_alibi_bits(rep_array_unsliced<y_type> y_accum, rep_array_unsliced<int> alibi_mask);

        // this is the old version of this function. Because I tried to do it with no reinserting, I was short on the
        // reinserted elements for anything more than building stupid into l0, which worked
    };
} // namespace emp
