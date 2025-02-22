#include "crypto/bilinear_group/matrix.h"
#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/schemes/tsps/verify.h"

#include "user/protocol.h"
namespace bookkeeping
{

//Creates a proof for the user's secret key
proof_sk_u User::create_proof_for_sk_u()
{
  GS::u_reg::GS_Input proof_input;
  proof_input.pk = {this->bls_sig.get_public_key()};
  proof_input.sk = {-this->bls_sig.get_secret_key() * BilinearGroup::G2::get_gen()};

  return {this->bls_sig.get_public_key(), GS::u_reg::prove(this->crs_nizk, proof_input)};
}

//Finalizes the registration of the user by verifying the threshold signature
bool User::finalize_registration(BilinearGroup::FP addr, tsps::SignatureM threshold_signature)
{
  std::vector<BilinearGroup::G1> message = {G1::koblitz_encode_message(addr), this->bls_sig.get_public_key()};
  if (tsps::verify(this->crs_tsps, message, this->vk_all, threshold_signature))
  {
    this->creds = {addr, threshold_signature};
    return true;
  }
  else
  {
    return false;
  }
} // namespace bookkeeping

} // namespace bookkeeping