#pragma once

#include "crypto/bookkeeping_proofs/prove_entry/out_types.hpp"
#include "crypto/proofs/prelude.hpp"
namespace GS
{
    namespace prove_entry
    {
        GS_Proof prove(CRS const &crs, GS_Input const &input);

    }
} // namespace GS