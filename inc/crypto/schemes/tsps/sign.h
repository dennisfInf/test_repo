#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/schemes/tsps/setup.h"

namespace tsps
{
struct SignatureM
{
  // Matrices are transposed vectors 1xDIM
  BilinearGroup::Matrix<BilinearGroup::G1> sig_1;
  BilinearGroup::Matrix<BilinearGroup::G1> sig_2;
  BilinearGroup::Matrix<BilinearGroup::G1> sig_3;
  BilinearGroup::G2 sig_4;
};

struct PartialSignature
{
  uint8_t party_id;
  SignatureM signature;
};

SignatureM parSign(const PublicParameters &pp, const BilinearGroup::Matrix<BilinearGroup::BN> &sk_i,
                   std::vector<BilinearGroup::G1> m);
SignatureM combineSign(uint8_t &n, std::vector<PartialSignature> &sigs);
} // namespace tsps