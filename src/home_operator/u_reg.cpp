#include "crypto/bookkeeping_proofs/setup.h"
#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/bookkeeping_proofs/u_reg/verifier.h"
#include "home_operator/protocol.h"
#include "user/structs.h"
namespace bookkeeping
{
  ThresholdSignature HomeOperator::register_user(bookkeeping::proof_sk_u &proof_sk_u, tsps::Protocol *tsps)
  {
    GS::u_reg::GS_Input_Public public_input;
    public_input.pk = {proof_sk_u.pk_u};
    if (!GS::u_reg::batch_verify(this->crs_nizk, proof_sk_u.proof, public_input))
    {
      throw std::invalid_argument("zkp not verified in register user");
    }
    std::lock_guard<std::mutex> lock(this->current_addr_mtx);
    BilinearGroup::FP addr = this->retrieve_current_addr();

    this->add_lkeys_entry({proof_sk_u.pk_u, addr});
    this->increment_addr();
    std::vector<BilinearGroup::G1> message = {BilinearGroup::G1::koblitz_encode_message(addr), proof_sk_u.pk_u};
    int message_id = tsps->get_current_message_id();
    auto start_verify_proof = std::chrono::high_resolution_clock::now();
    std::cout << "il here" << std::endl;
    tsps::SignatureM signature = tsps->sign_message(message, message_id, proof_sk_u.proof);
    auto end_verify_proof = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_verify_proof = end_verify_proof - start_verify_proof;
    std::cout << "tsps verify time: " << elapsed_verify_proof.count() << " seconds" << std::endl;

    return {signature, addr};
    // Use *sig to access the tsps::SignatureM value
  }
} // namespace bookkeeping