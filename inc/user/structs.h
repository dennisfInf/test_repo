#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "crypto/bookkeeping_proofs/prove_entry/out_types.hpp"

#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/schemes/threshold_el_gamal/participant.h"
#include "crypto/schemes/tsps/sign.h"

namespace bookkeeping
{
  struct proof_sk_u
  {
    BilinearGroup::G1 pk_u;
    GS::u_reg::GS_Proof proof;
  };

  struct proof_create_entry
  {
    Participants::ciphertext_r ciphertext_r;
    std::vector<uint8_t> hash;
    GS::zkp::GS_Proof proof;
  };

  struct proof_prove_entry
  {
    Participants::ciphertext ciphertext;
    BilinearGroup::G2 sig_entry;
    BilinearGroup::BN message;
    BilinearGroup::FP addr;
    BilinearGroup::BN period;
    tsps::SignatureM threshold_signature;
    BilinearGroup::G1 pk_u;
    GS::prove_entry::GS_Proof proof;
  };

  struct credentials
  {
    BilinearGroup::FP addr;
    tsps::SignatureM threshold_signature;
  };

  struct Entry
  {
    BilinearGroup::BN message;
    Participants::ciphertext_r ct_u;
    BilinearGroup::G2 sig_entry;
    // left out the vk_ho here, because it is already stored
  };

}; // namespace bookkeeping