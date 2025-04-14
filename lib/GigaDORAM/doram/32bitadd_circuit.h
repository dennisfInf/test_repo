#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include <cmath>
using namespace emp;
using namespace std;

namespace gc
{
    uint32_t *add(const int party, HighSpeedNetIO *io, uint32_t share_pointer, uint32_t share_limit);

};