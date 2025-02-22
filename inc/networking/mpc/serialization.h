#pragma once
#include "Math/gfp.h"
#include "Math/bigint.h"
#include "Math/gfpvar.h"
#include "crypto/bilinear_group/group.h"
#include "vector"

namespace MPC
{
bigint deserialize_bytes(const std::vector<uint8_t> &bytes);
gfp conv_bn_to_gfp(BilinearGroup::BN  &val);
gfpvar_<1,6> conv_bn_to_gfpvar(BilinearGroup::BN &val);
void test_serialization();
BilinearGroup::BN conv_decimal_string_to_bn(std::string &str);
BilinearGroup::BN conv_bigint_to_bn(const bigint &val);
BilinearGroup::BN conv_gfp_to_bn(const gfp &val);
} // namespace MPC