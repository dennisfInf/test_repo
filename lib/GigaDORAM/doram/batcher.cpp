#include "globals.h"
#include "batcher.h"

namespace emp
{
    namespace batcher
    {
        uint64_t least_power_of_2_greater_than_or_equal_to(uint64_t len)
        {
            return 1ULL << (8 * sizeof(uint64_t) - __builtin_clzll(len - 1));
        }
    }
}