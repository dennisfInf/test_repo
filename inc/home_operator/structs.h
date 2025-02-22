#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "crypto/schemes/threshold_el_gamal/participant.h"
namespace bookkeeping
{
  struct LKey
  {
    BilinearGroup::G1 pk_u;
    BilinearGroup::FP addr;
    bool operator==(const LKey &other) const
    {
      return pk_u == other.pk_u && addr == other.addr;
    }
  };

  struct proof_create_entry_user
  {
    Participants::ciphertext ciphertext;
    // ssid
    GS::zkp::GS_Proof proof;
    //  proof_sk_u
  };
  struct PendingEntry
  {
    BilinearGroup::BN period;
    proof_create_entry_user proof;
    BilinearGroup::BN msg;
  };

  struct BenchmarkInsertEntry
  {
    double total_time;
    double mpc1_time;
    double mpc2_time;
  };

}; // namespace bookkeeping