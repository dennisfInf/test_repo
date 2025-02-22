#include "ohtable_array.h"
namespace emp
{
    double time_before_cht, time_in_cht, time_after_cht, time_ite;

    uint prf_key_size_blocks()
    {
        assert(prf_circuit != nullptr);
        uint bits_per_block = 8 * sizeof(block); // 128
        assert(prf_circuit->num_input % bits_per_block == 0);
        return prf_circuit->num_input / bits_per_block - 1;
    }

    ostream &operator<<(ostream &stream, const OHTableParams &params)
    {
        stream << "OHTable {\n";
        stream << "size: " << params.total_size() << '\n';
        stream << "num_elements: " << params.num_elements << '\n';
        stream << "num_dummies: " << params.num_dummies << '\n';
        stream << "stash_size: " << params.stash_size << '\n';
        stream << "builder: " << params.builder << '\n';
        stream << "cht_log_single_col_len: " << params.cht_log_single_col_len << '\n';
        return stream << "}\n";
    }
}