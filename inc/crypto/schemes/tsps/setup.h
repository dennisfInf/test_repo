#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/schemes/tsps/matrix_dist.h"
#include <variant>

namespace tsps
{
struct PublicParameters
{
  BilinearGroup::Matrix<BilinearGroup::G2> A;
  BilinearGroup::Matrix<BilinearGroup::G2> UA;
  BilinearGroup::Matrix<BilinearGroup::G2> VA;
  BilinearGroup::Matrix<BilinearGroup::G1> B;
  BilinearGroup::Matrix<BilinearGroup::G1> BtU;
  BilinearGroup::Matrix<BilinearGroup::G1> BtV;
};

uint8_t public_parameters_size();
PublicParameters create_public_params(const uint8_t &k);


} // namespace tsps