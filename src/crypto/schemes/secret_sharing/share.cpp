#include "crypto/schemes/secret_sharing/share.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "networking/grpc/serialize.h"
#include <iostream>
using namespace Participants;

bool Share::verify(const Commitments::DKG__Commitment &commitment, const uint8_t &my_index)
{
  if (my_index != this->receiver_index)
  {
    std::cout << "receiver index does not match" << std::endl;
    return false;
  }
  BilinearGroup::G1 pub_share;
  std::future<void> f =
      BilinearGroup::pool.push([this, &pub_share](int) { pub_share = BilinearGroup::G1::get_gen() * this->share; });

  BilinearGroup::BN receiver_index = BilinearGroup::BN(this->receiver_index);
  BilinearGroup::G1 result = Polynomial::Horners_method<BilinearGroup::G1>(
      commitment.commitments, receiver_index, BilinearGroup::G1::get_infty(), commitment.commitments.size(), 1);
  result += commitment.commitments[0];
  f.wait();
  if (pub_share == result)
  {
    return true;
  }
  std::cout << "shares results do not match" << std::endl;
  return false;
}
BilinearGroup::BN Share::operator+(const BilinearGroup::BN &x) const { return this->share + x; }