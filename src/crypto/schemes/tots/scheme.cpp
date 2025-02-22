#include "crypto/schemes/tots/scheme.h"
#include "crypto/bilinear_group/matrix.h"
namespace tots
{
Signature tots::OTS::sign(std::vector<uint8_t> message)
{
  BilinearGroup::BN r_0 = BilinearGroup::BN::rand();

  BilinearGroup::G1 C_0 = BilinearGroup::BN::hash_to_group(message) * BilinearGroup::G1::get_gen() + r_0 * this->H;

  BilinearGroup::BN w_inv;

  BilinearGroup::BN::mod_inverse(w_inv, this->key_mat.w, BilinearGroup::G1::get_group_order());

  BilinearGroup::BN r_1 = (this->key_mat.s - BilinearGroup::hash_G1_elements<BilinearGroup::BN>({C_0})) * w_inv;
  return {r_0, r_1};
};

bool tots::OTS::verify(std::vector<uint8_t> message, Signature sig, PublicKey pk, BilinearGroup::G1 H)
{
  BilinearGroup::G1 C_0 = BilinearGroup::BN::hash_to_group(message) * BilinearGroup::G1::get_gen() + sig.r_0 * H;
  BilinearGroup::G1 C_1 =
      BilinearGroup::hash_G1_elements<BilinearGroup::BN>({C_0}) * BilinearGroup::G1::get_gen() + sig.r_1 * pk.H_1;
  return pk.C_1 == C_1;
};
} // namespace tots