#pragma once
#include "crypto/proofs/prelude.hpp"
#include <chrono>
namespace GS
{
namespace zkp
{
void build_tables(CRS &crs);
CRS generate_crs();
std::unique_ptr<CRS> setup_crs();
} // namespace zkp
} // namespace GS