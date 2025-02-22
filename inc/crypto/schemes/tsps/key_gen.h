#pragma once

#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/secret_sharing/share.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "networking/client.h"
#include "networking/grpc/tsps.h"

namespace tsps
{

  class Key
  {
  public:
    Key(size_t row, size_t col, uint n)
        : secret_share(row, col, BilinearGroup::BN::get_infty()),
          public_key(row, col - 1, BilinearGroup::G2::get_infty()), public_shares(n)
    {
    }
    Key(Key &key)
    {
      this->secret_share = key.secret_share;
      this->public_key = key.public_key;
      this->public_shares = key.public_shares;
      this->public_share = key.public_share;
    }
    BilinearGroup::Matrix<BilinearGroup::BN> get_secret_share() { return this->secret_share; }
    void set_secret_share(const uint8_t &row, const uint8_t &col, const BilinearGroup::BN &secret)
    {
      this->secret_share(row, col) = secret;
    }
    void set_public_share(const BilinearGroup::Matrix<BilinearGroup::G2> &A, const uint8_t &index, const uint8_t &n)
    {
      this->public_share = this->secret_share * A;
      add_verification_key(this->public_share, index, n);
    }
    BilinearGroup::Matrix<BilinearGroup::G2> get_public_share() { return this->public_share; }
    BilinearGroup::Matrix<BilinearGroup::G2> get_public_key() { return this->public_key; }
    std::vector<BilinearGroup::Matrix<BilinearGroup::G2>> get_public_shares() { return this->public_shares; }

    void add_verification_key(const BilinearGroup::Matrix<BilinearGroup::G2> &vk, const uint8_t &index,
                              const uint8_t &n)
    {
      std::lock_guard<std::mutex> lock(this->mtx);
      public_shares[index - 1] = vk;
      this->public_key += vk * Polynomial::get_lagrange_coeff(BilinearGroup::BN(0), index, n);
    }

  private:
    std::mutex mtx;
    BilinearGroup::Matrix<BilinearGroup::BN> secret_share;
    BilinearGroup::Matrix<BilinearGroup::G2> public_key;
    BilinearGroup::Matrix<BilinearGroup::G2> public_share;
    std::vector<BilinearGroup::Matrix<BilinearGroup::G2>> public_shares;
  };
} // namespace tsps