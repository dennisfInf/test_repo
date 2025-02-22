#pragma once

#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "crypto/proofs/prelude.hpp"
namespace GS
{
namespace zkp
{
GS_Proof prove(CRS const &crs, GS_Input const &input);

}
} // namespace GS