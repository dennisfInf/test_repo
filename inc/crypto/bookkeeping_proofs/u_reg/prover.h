#pragma once
#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/proofs/prelude.hpp"
namespace GS
{
namespace u_reg
{
GS_Proof prove(CRS const &crs, GS_Input const &input);

}
} // namespace GS