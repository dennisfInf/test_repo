#include "home_operator/protocol.h"
#include "crypto/gc/32bitadd_circuit.h"

namespace bookkeeping
{
    void HomeOperator::setup_oram()
    {
        x_type limit = 301;
        for (int i = 0; i < 5000; i++)
        {
            int is_write = 1;
            emp::rep_array_unsliced<int> is_write_rep(1);
            is_write_rep.input_public(&is_write);
            emp::rep_array_unsliced<emp::x_type> user_pointer(1);
            x_type pointer_index = 1 + i * 301;
            user_pointer.input_public(&pointer_index);
            emp::rep_array_unsliced<emp::y_type> pointer_and_limit(1);
            emp::y_type y_val = static_cast<emp::y_type>(pointer_index) << 32 | static_cast<emp::y_type>(limit);
            pointer_and_limit.input_public(&y_val);
            doram.read_and_write(user_pointer, pointer_and_limit, is_write_rep);
        }
    }
    Query HomeOperator::read_pointer_from_oram(emp::x_type &pointer_index_share)
    {
        int is_write = 0;
        emp::rep_array_unsliced<int> is_write_rep(1);
        is_write_rep.input_public(&is_write);
        emp::rep_array_unsliced<emp::x_type> x_query(1);
        x_query.input_xor(1, &pointer_index_share);
        x_query.input_xor(2, &pointer_index_share);
        emp::rep_array_unsliced<emp::y_type> y_qry_rep(1);
        return {x_query, doram.read_and_write(x_query, y_qry_rep, is_write_rep)};
    };

    void HomeOperator::insert_message_in_oram(emp::rep_array_unsliced<emp::y_type> &x_query_base, emp::rep_array_unsliced<emp::x_type> &pointer_index, std::vector<emp::y_type> &y_queries)
    {
        std::cout << "inserting message" << std::endl;
        if (y_queries.size() != 3)
        {
            std::cout << "size of y values is " << y_queries.size() << " instead of 3" << std::endl;
            exit(1);
        }
        int is_write = 1;
        emp::rep_array_unsliced<int> is_write_rep(1);
        is_write_rep.input_public(&is_write);

        emp::rep_array_unsliced<emp::x_type> x_query(1);
        x_query.copy_bytes_from(x_query_base, sizeof(emp::x_type));

        emp::rep_array_unsliced<emp::x_type> limit(1);
        limit.copy_bytes_from(x_query_base, sizeof(emp::x_type), sizeof(emp::x_type));

        // write msg to ORAM
        uint32_t *pointers = new uint32_t[3];
        if (emp::party != 3)
        {

            x_type pointer_share;
            x_query.get_share(emp::party, &pointer_share);
            x_type limit_share;
            limit.get_share(emp::party, &limit_share);
            emp::HighSpeedNetIO *io_2 = new emp::HighSpeedNetIO(emp::party == 1 ? nullptr : bootstrap_addr.c_str(), 51000, 51000 + 1);

            pointers = gc::add(emp::party, io_2, pointer_share, limit_share);
            delete io_2;
        }
        emp::rep_array_unsliced<emp::x_type> pointer(1);

        for (int i = 0; i < 3; i++)
        {
            pointer.input_xor(1, &pointers[i]);
            pointer.input_xor(2, &pointers[i]);
            emp::rep_array_unsliced<emp::y_type> y_qry_rep(1);
            y_qry_rep.input_public(&y_queries[i]);
            doram.read_and_write(pointer, y_qry_rep, is_write_rep);
        }
        // Update pointer in ORAM
        // use last pointer and add limit
        emp::rep_array_unsliced<emp::x_type> x_qry_rep(1);
        emp::rep_array_unsliced<emp::y_type> y_qry_rep(1);
        y_qry_rep.copy_bytes_from(pointer, sizeof(emp::x_type));
        y_qry_rep.copy_bytes_from(limit, 0, sizeof(emp::x_type), sizeof(emp::x_type));

        doram.read_and_write(pointer_index, y_qry_rep, is_write_rep);
        delete pointers;
    }
}