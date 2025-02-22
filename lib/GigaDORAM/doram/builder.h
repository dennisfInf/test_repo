#pragma once

#include <iostream>
#include <map>
#include <unistd.h> // for nonblocking
#include <math.h>

#include "bristol_fashion_array.h"
#include "debug.h"
#include "doram_array.h"
#include "globals.h" //player's global pessions
// already included through DORAM: #include "doram/sh_rep_bin.h" //needed for circ_exec type

#include "emp-tool/emp-tool.h"
#include "emp-tool/utils/block.h" //inputs to AES are blocks

using namespace std;

namespace emp
{
    // DORAM params

    void initialize_resource_set(int resource_id, string prev_host, string next_host, int prev_port, int next_port);

    void initialize_all_resources(string prev_host, string next_host, int prev_port, int next_port);

    rep_array_unsliced<y_type> *init(int party_index, string prev_host_and_port, string next_host_and_port, bool BUILD_BOTTOM_LEVEL_AT_STARTUP, uint LOG_ADDRESS_SPACE, uint NUM_LEVELS, uint LOG_AMP_FACTOR, int NUM_THREADS);
}