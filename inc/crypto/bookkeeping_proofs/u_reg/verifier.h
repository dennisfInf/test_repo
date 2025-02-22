#pragma once
#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/tots/scheme.h"

namespace GS
{
namespace u_reg
{
bool verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
bool batch_verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
} // namespace zkp
} // namespace GS