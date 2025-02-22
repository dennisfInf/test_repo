#include "debug.h"

namespace emp
{
    void dbg_out()
    {
        cerr << "\n"; // removed endl to allow more efficient printing
    }
}