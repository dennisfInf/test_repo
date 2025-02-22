#pragma once

#include "crypto/schemes/tsps/setup.h"
#include "crypto/schemes/tsps/sign.h"
namespace tsps
{
    bool verify(const PublicParameters &public_params, std::vector<BilinearGroup::G1> message,
                const BilinearGroup::Matrix<BilinearGroup::G2> &public_key, const SignatureM &sign);
   
}