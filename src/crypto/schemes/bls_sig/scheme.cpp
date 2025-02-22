#include "crypto/schemes/bls_sig/scheme.h"
#include "crypto/bilinear_group/group.h"
namespace BLS
{
Signature Signatures::sign_message(std::vector<uint8_t> m)
{
  BilinearGroup::G2 msg = BilinearGroup::G2::hash_to_group(m);
  return {this->secret_key * msg, msg};
}

bool Signatures::verify_signature(std::vector<uint8_t> m, BilinearGroup::G2 sig, BilinearGroup::G1 pk)
{
  BilinearGroup::GT left;
  std::future<void> f = BilinearGroup::pool.push([&left, &sig](int)
                                                 { left = BilinearGroup::GT::map(BilinearGroup::G1::get_gen(), sig); });
  BilinearGroup::GT right = BilinearGroup::GT::map(pk, BilinearGroup::G2::hash_to_group(m));
  f.wait();
  return left == right;
}
} // namespace BLS