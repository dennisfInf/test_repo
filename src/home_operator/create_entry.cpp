#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "crypto/bookkeeping_proofs/create_entry/verifier.h"
#include "home_operator/protocol.h"
#include "user/protocol.h"
namespace bookkeeping
{

  bool HomeOperator::verify_create_entry_proof(proof_create_entry_user &p_ce, std::vector<uint8_t> &h, tsps::Protocol *tsps)
  {
    GS::zkp::GS_Input_Public public_input;
    public_input.ct1 = {p_ce.ciphertext.c1};
    public_input.ct2 = {p_ce.ciphertext.c2};
    public_input.ek = {this->el_gamal.get_public_key()};
    tsps::PublicParameters crs_tsps = tsps->get_public_parameters();

    public_input.ppA11 = {crs_tsps.A(0, 0)};
    public_input.ppA21 = {crs_tsps.A(1, 0)};

    public_input.ppB11 = {crs_tsps.B(0, 0)};
    public_input.ppB21 = {crs_tsps.B(1, 0)};

    public_input.ppBtU11 = {crs_tsps.BtU(0, 0)};
    public_input.ppBtU12 = {crs_tsps.BtU(0, 1)};

    public_input.ppBtV11 = {crs_tsps.BtV(0, 0)};
    public_input.ppBtV12 = {crs_tsps.BtV(0, 1)};

    public_input.ppUA11 = {crs_tsps.UA(0, 0)};
    public_input.ppUA21 = {crs_tsps.UA(1, 0)};

    public_input.ppVA11 = {crs_tsps.VA(0, 0)};
    public_input.ppVA21 = {crs_tsps.VA(1, 0)};

    BilinearGroup::Matrix<BilinearGroup::G2> vk_all = tsps->get_public_key();
    public_input.vk11 = {vk_all(0, 0)};
    public_input.vk21 = {vk_all(1, 0)};
    public_input.vk31 = {vk_all(2, 0)};
    public_input.h = {BilinearGroup::G2::hash_to_group(h)};
    return GS::zkp::batch_verify(this->crs_nizk, p_ce.proof, public_input);
  }

  BLS::Signature HomeOperator::create_entry(proof_create_entry_user &p_ce, BilinearGroup::BN &msg,
                                            BilinearGroup::BN &period, tsps::Protocol* tsps)
  {
    auto start_hash = std::chrono::high_resolution_clock::now();

    std::vector<uint8_t> h = hash_elements(period, msg, p_ce.ciphertext);
    auto end_hash = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_ce = end_hash - start_hash;
    std::cout << "hash time: " << elapsed_ce.count() << " seconds" << std::endl;
    if (this->verify_create_entry_proof(p_ce, h, tsps))
    {
      std::cout << "zkp verified  in create_entry  !" << std::endl;
      this->l_pending.push({period, p_ce, msg});
      BLS::Signature sig = this->bls_sig.sign_message(h);
      return sig;
    }
    else
    {

      throw std::invalid_argument("zkp not verified in create_entry");
    }

    // Return Signature to user
  }
} // namespace bookkeeping