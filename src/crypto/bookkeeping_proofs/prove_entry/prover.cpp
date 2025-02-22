
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/tots/scheme.h"
#include "crypto/bookkeeping_proofs/prove_entry/prover.h"

namespace GS
{
  using namespace std;
  using namespace BilinearGroup;
  namespace prove_entry
  {

    bool consistency_check_e01(GS_Input const &input)
    {
      auto lhs =
          input.ct1.value * BN(1) * input.g2.value +
          input.g1.value * BN(1) * input.rinv.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }
    bool consistency_check_e02(GS_Input const &input)
    {
      auto lhs =
          input.ct2.value * BN(1) * input.g2.value +
          input.ek.value * BN(1) * input.rinv.value +
          input.addr.value * BN(-1) * input.g2.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }

    bool consistency_check_e03(GS_Input const &input)
    {
      auto lhs =
          input.pk.value * BN(1) * input.sk.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }

    bool consistency_check(GS_Input const &input)
    {

      return

          consistency_check_e01(input) && consistency_check_e02(input) && consistency_check_e03(input);
    }

    auto prove_eq_e01(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_ct1branch0_pi1 = commitments.ct1branch0 - v_1 * commitments.ct1branch0.rand_r;
      auto precomp_g1branch0_pi1 = commitments.g1branch0 - v_1 * commitments.g1branch0.rand_r - w_1 * commitments.g1branch0.rand_s;
      proof.pi_v_1 = commitments.g2 * BN(1) * commitments.ct1branch0.rand_r + commitments.rinv * BN(1) * commitments.g1branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ct1branch0_pi1 * BN(1) * commitments.g2.rand_r + precomp_g1branch0_pi1 * BN(1) * commitments.rinv.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.g2 * BN(1) * commitments.ct1branch0.rand_s + commitments.rinv * BN(1) * commitments.g1branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ct1branch0_pi1 * BN(1) * commitments.g2.rand_s + precomp_g1branch0_pi1 * BN(1) * commitments.rinv.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e82(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_ct2branch0_pi1 = commitments.ct2branch0 - v_1 * commitments.ct2branch0.rand_r;
      auto precomp_ct2_pi1 = commitments.ct2;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ct2branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ct2.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ct2branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ct2_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ct2branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ct2.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ct2branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ct2_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e91(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_zkPKbranch1_pi1 = commitments.zkPKbranch1 - v_1 * commitments.zkPKbranch1.rand_r;
      auto precomp_zkPK_pi1 = commitments.zkPK;
      proof.pi_v_1 = commitments.branch1 * BN(1) * commitments.zkPKbranch1.rand_r + commitments.branch1 * BN(-1) * commitments.zkPK.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_zkPKbranch1_pi1 * BN(1) * commitments.branch1.rand_r + precomp_zkPK_pi1 * BN(-1) * commitments.branch1.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch1 * BN(1) * commitments.zkPKbranch1.rand_s + commitments.branch1 * BN(-1) * commitments.zkPK.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_zkPKbranch1_pi1 * BN(1) * commitments.branch1.rand_s + precomp_zkPK_pi1 * BN(-1) * commitments.branch1.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e80(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_pk_pi1 = commitments.pk;
      auto precomp_pkbranch0_pi1 = commitments.pkbranch0 - v_1 * commitments.pkbranch0.rand_r;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.pk.rand_r + commitments.branch0 * BN(1) * commitments.pkbranch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_pk_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_pkbranch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.pk.rand_s + commitments.branch0 * BN(1) * commitments.pkbranch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_pk_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_pkbranch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e81(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_ct1_pi1 = commitments.ct1;
      auto precomp_ct1branch0_pi1 = commitments.ct1branch0 - v_1 * commitments.ct1branch0.rand_r;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.ct1.rand_r + commitments.branch0 * BN(1) * commitments.ct1branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ct1_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_ct1branch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.ct1.rand_s + commitments.branch0 * BN(1) * commitments.ct1branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ct1_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_ct1branch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e70(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_g1_pi1 = commitments.g1;
      proof.pi_v_1 = commitments.g2 * BN(1) * commitments.g1.rand_r + commitments.branch0 * BN(-1) * commitments.g1.rand_r + commitments.branch1 * BN(-1) * commitments.g1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1_pi1 * BN(1) * commitments.g2.rand_r + precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.g2 * BN(1) * commitments.g1.rand_s + commitments.branch0 * BN(-1) * commitments.g1.rand_s + commitments.branch1 * BN(-1) * commitments.g1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1_pi1 * BN(1) * commitments.g2.rand_s + precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e03(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_pkbranch0_pi1 = commitments.pkbranch0 - v_1 * commitments.pkbranch0.rand_r;
      auto precomp_g1branch0_pi1 = commitments.g1branch0 - v_1 * commitments.g1branch0.rand_r - w_1 * commitments.g1branch0.rand_s;
      proof.pi_v_1 = commitments.g2 * BN(1) * commitments.pkbranch0.rand_r + commitments.sk * BN(1) * commitments.g1branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_pkbranch0_pi1 * BN(1) * commitments.g2.rand_r + precomp_g1branch0_pi1 * BN(1) * commitments.sk.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.g2 * BN(1) * commitments.pkbranch0.rand_s + commitments.sk * BN(1) * commitments.g1branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_pkbranch0_pi1 * BN(1) * commitments.g2.rand_s + precomp_g1branch0_pi1 * BN(1) * commitments.sk.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e90(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_g1branch1_pi1 = commitments.g1branch1 - v_1 * commitments.g1branch1.rand_r - w_1 * commitments.g1branch1.rand_s;
      auto precomp_g1_pi1 = commitments.g1;
      proof.pi_v_1 = commitments.branch1 * BN(1) * commitments.g1branch1.rand_r + commitments.branch1 * BN(-1) * commitments.g1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1branch1_pi1 * BN(1) * commitments.branch1.rand_r + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch1 * BN(1) * commitments.g1branch1.rand_s + commitments.branch1 * BN(-1) * commitments.g1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1branch1_pi1 * BN(1) * commitments.branch1.rand_s + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e60(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_g1branch1_pi1 = commitments.g1branch1 - v_1 * commitments.g1branch1.rand_r - w_1 * commitments.g1branch1.rand_s;
      auto precomp_zkPKbranch1_pi1 = commitments.zkPKbranch1 - v_1 * commitments.zkPKbranch1.rand_r;
      proof.pi_v_1 = commitments.zkHash * BN(1) * commitments.g1branch1.rand_r + commitments.zkSig * BN(-1) * commitments.g1branch1.rand_r + commitments.g2 * BN(1) * commitments.zkPKbranch1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1branch1_pi1 * BN(1) * commitments.zkHash.rand_r + precomp_g1branch1_pi1 * BN(-1) * commitments.zkSig.rand_r + precomp_zkPKbranch1_pi1 * BN(1) * commitments.g2.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.zkHash * BN(1) * commitments.g1branch1.rand_s + commitments.zkSig * BN(-1) * commitments.g1branch1.rand_s + commitments.g2 * BN(1) * commitments.zkPKbranch1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1branch1_pi1 * BN(1) * commitments.zkHash.rand_s + precomp_g1branch1_pi1 * BN(-1) * commitments.zkSig.rand_s + precomp_zkPKbranch1_pi1 * BN(1) * commitments.g2.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e02(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_ekbranch0_pi1 = commitments.ekbranch0 - v_1 * commitments.ekbranch0.rand_r;
      auto precomp_addr_pi1 = commitments.addr;
      auto precomp_ct2branch0_pi1 = commitments.ct2branch0 - v_1 * commitments.ct2branch0.rand_r;
      proof.pi_v_1 = commitments.rinv * BN(1) * commitments.ekbranch0.rand_r + commitments.g2 * BN(-1) * commitments.addr.rand_r + commitments.g2 * BN(1) * commitments.ct2branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ekbranch0_pi1 * BN(1) * commitments.rinv.rand_r + precomp_addr_pi1 * BN(-1) * commitments.g2.rand_r + precomp_ct2branch0_pi1 * BN(1) * commitments.g2.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.rinv * BN(1) * commitments.ekbranch0.rand_s + commitments.g2 * BN(-1) * commitments.addr.rand_s + commitments.g2 * BN(1) * commitments.ct2branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ekbranch0_pi1 * BN(1) * commitments.rinv.rand_s + precomp_addr_pi1 * BN(-1) * commitments.g2.rand_s + precomp_ct2branch0_pi1 * BN(1) * commitments.g2.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }
    auto prove_eq_e83(CRS const &crs, GS_Commitments const &commitments)
    {
      EQ_Proof proof;
      G1Vec v_1;
      G1Vec w_1;
      crs.v(v_1);
      crs.w(w_1);
      G2Vec v_2;
      G2Vec w_2;
      crs.v(v_2);
      crs.w(w_2);

      BN alpha = BN::rand();
      BN beta = BN::rand();
      BN gamma = BN::rand();
      BN delta = BN::rand();
      auto precomp_ek_pi1 = commitments.ek;
      auto precomp_ekbranch0_pi1 = commitments.ekbranch0 - v_1 * commitments.ekbranch0.rand_r;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.ek.rand_r + commitments.branch0 * BN(1) * commitments.ekbranch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ek_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_ekbranch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.ek.rand_s + commitments.branch0 * BN(1) * commitments.ekbranch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ek_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_ekbranch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    GS_Proof prove(CRS const &crs, GS_Input const &input)
    {
      GS_Proof proof;
      tots::OTS tots = tots::OTS(crs.H);
      proof.ots_pk = tots.get_public_key();
      auto ct1branch0 = pool.push([&](int) -> auto
                                  { proof.commitments.ct1branch0 = commit(crs, EncVarG1{input.ct1.value}); return 0; });
      auto g1branch0 = pool.push([&](int) -> auto
                                 { proof.commitments.g1branch0 = commit(crs, ComVarG1{G1::get_gen()}); return 0; });
      auto rinv = pool.push([&](int) -> auto
                            { proof.commitments.rinv = commit(crs, input.rinv); return 0; });
      auto ct2branch0 = pool.push([&](int) -> auto
                                  { proof.commitments.ct2branch0 = commit(crs, EncVarG1{input.ct2.value}); return 0; });
      auto branch0 = pool.push([&](int) -> auto
                               { proof.commitments.branch0 = commit(crs, ComVarG2{G2::get_gen()}); return 0; });
      auto zkPKbranch1 = pool.push([&](int) -> auto
                                   { proof.commitments.zkPKbranch1 = commit(crs, EncVarG1{G1::get_infty()}); return 0; });
      auto branch1 = pool.push([&](int) -> auto
                               { proof.commitments.branch1 = commit(crs, ComVarG2{G2::get_infty()}); return 0; });
      auto pkbranch0 = pool.push([&](int) -> auto
                                 { proof.commitments.pkbranch0 = commit(crs, EncVarG1{input.pk.value}); return 0; });
      auto sk = pool.push([&](int) -> auto
                          { proof.commitments.sk = commit(crs, input.sk); return 0; });
      auto g1branch1 = pool.push([&](int) -> auto
                                 { proof.commitments.g1branch1 = commit(crs, ComVarG1{G1::get_infty()}); return 0; });
      auto zkSig = pool.push([&](int) -> auto
                             { proof.commitments.zkSig = commit(crs, EncVarG2{G2::get_infty()}); return 0; });
      auto ekbranch0 = pool.push([&](int) -> auto
                                 { proof.commitments.ekbranch0 = commit(crs, EncVarG1{input.ek.value}); return 0; });

      proof.commitments.g2 = commit(crs, input.g2);
      proof.commitments.ct2 = commit(crs, input.ct2);
      proof.commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});
      proof.commitments.pk = commit(crs, input.pk);
      proof.commitments.ct1 = commit(crs, input.ct1);
      proof.commitments.g1 = commit(crs, input.g1);
      proof.commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
      proof.commitments.addr = commit(crs, input.addr);
      proof.commitments.ek = commit(crs, input.ek);

      ct1branch0.get();
      g1branch0.get();
      rinv.get();
      ct2branch0.get();
      branch0.get();
      zkPKbranch1.get();
      branch1.get();
      pkbranch0.get();
      sk.get();
      g1branch1.get();
      zkSig.get();
      ekbranch0.get();

      auto eq_e01 = pool.push([&](int) -> auto
                              { proof.eq_e01 = prove_eq_e01(crs, proof.commitments); return 0; });
      auto eq_e82 = pool.push([&](int) -> auto
                              { proof.eq_e82 = prove_eq_e82(crs, proof.commitments); return 0; });
      auto eq_e91 = pool.push([&](int) -> auto
                              { proof.eq_e91 = prove_eq_e91(crs, proof.commitments); return 0; });
      auto eq_e80 = pool.push([&](int) -> auto
                              { proof.eq_e80 = prove_eq_e80(crs, proof.commitments); return 0; });
      auto eq_e81 = pool.push([&](int) -> auto
                              { proof.eq_e81 = prove_eq_e81(crs, proof.commitments); return 0; });
      auto eq_e70 = pool.push([&](int) -> auto
                              { proof.eq_e70 = prove_eq_e70(crs, proof.commitments); return 0; });
      auto eq_e03 = pool.push([&](int) -> auto
                              { proof.eq_e03 = prove_eq_e03(crs, proof.commitments); return 0; });
      auto eq_e90 = pool.push([&](int) -> auto
                              { proof.eq_e90 = prove_eq_e90(crs, proof.commitments); return 0; });
      auto eq_e60 = pool.push([&](int) -> auto
                              { proof.eq_e60 = prove_eq_e60(crs, proof.commitments); return 0; });
      auto eq_e02 = pool.push([&](int) -> auto
                              { proof.eq_e02 = prove_eq_e02(crs, proof.commitments); return 0; });
      auto eq_e83 = pool.push([&](int) -> auto
                              { proof.eq_e83 = prove_eq_e83(crs, proof.commitments); return 0; });
      eq_e01.get();
      eq_e82.get();
      eq_e91.get();
      eq_e80.get();
      eq_e81.get();
      eq_e70.get();
      eq_e03.get();
      eq_e90.get();
      eq_e60.get();
      eq_e02.get();
      eq_e83.get();
      std::vector<uint8_t> buffer;
      Serializer serializer(buffer);
      proof.serialize_without_sig(serializer);
      std::vector<uint8_t> proof_hash = BilinearGroup::hash(buffer.data(), buffer.size());
      proof.ots_sig = tots.sign(proof_hash);
      return proof;
    }

  } // namespace prove_entry
} // namespace GS
