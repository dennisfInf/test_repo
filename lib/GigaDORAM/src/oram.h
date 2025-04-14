#pragma once
#include "doram_array.h"
#include "rep_array_unsliced.h"
namespace DORAM
{

    struct Query
    {
        emp::rep_array_unsliced<emp::x_type> x_value;
        emp::rep_array_unsliced<emp::y_type> y_value;
    };

    void setup_oram(emp::DORAM &doram);

    Query read_pointer_from_oram(emp::DORAM &doram, emp::x_type &pointer_index_share);

    void insert_message_in_oram(emp::DORAM &doram, emp::rep_array_unsliced<emp::y_type> &x_query_base, emp::rep_array_unsliced<emp::x_type> &pointer_index, std::vector<emp::y_type> y_queries, std::string &party1_addr);
}