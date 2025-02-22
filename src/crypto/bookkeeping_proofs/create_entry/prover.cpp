
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/tots/scheme.h"
#include "crypto/bookkeeping_proofs/create_entry/prover.h"

namespace GS
{
  using namespace std;
  using namespace BilinearGroup;
  namespace zkp
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
          input.g1.value * BN(-1) * input.siguser.value +
          input.pk.value * BN(1) * input.h.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }
    bool consistency_check_e04(GS_Input const &input)
    {
      auto lhs =
          input.fsig11.value * BN(-1) * input.ppA11.value +
          input.ssig11.value * BN(1) * input.ppUA11.value +
          input.ssig12.value * BN(1) * input.ppUA21.value +
          input.tsig12.value * BN(1) * input.ppVA21.value +
          input.tsig11.value * BN(1) * input.ppVA11.value +
          input.g1.value * BN(1) * input.vk11.value +
          input.fsig12.value * BN(-1) * input.ppA21.value +
          input.pk.value * BN(1) * input.vk31.value +
          input.addr.value * BN(1) * input.vk21.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }
    bool consistency_check_e05(GS_Input const &input)
    {
      auto lhs =
          input.ssig11.value * BN(1) * input.fosig.value +
          input.tsig11.value * BN(-1) * input.g2.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }
    bool consistency_check_e06(GS_Input const &input)
    {
      auto lhs =
          input.tsig12.value * BN(-1) * input.g2.value +
          input.ssig12.value * BN(1) * input.fosig.value;
      auto rhs = GT::get_unity();
      return lhs == rhs;
    }
    bool consistency_check(GS_Input const &input)
    {

      return

          consistency_check_e01(input) && consistency_check_e02(input) && consistency_check_e03(input) && consistency_check_e04(input) && consistency_check_e05(input) && consistency_check_e06(input);
    }

    auto prove_eq_e04(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_fsig11_pi1 = commitments.fsig11 - v_1 * commitments.fsig11.rand_r - w_1 * commitments.fsig11.rand_s;
      auto precomp_ssig11_pi1 = commitments.ssig11 - v_1 * commitments.ssig11.rand_r - w_1 * commitments.ssig11.rand_s;
      auto precomp_ssig12_pi1 = commitments.ssig12 - v_1 * commitments.ssig12.rand_r - w_1 * commitments.ssig12.rand_s;
      auto precomp_tsig12_pi1 = commitments.tsig12 - v_1 * commitments.tsig12.rand_r - w_1 * commitments.tsig12.rand_s;
      auto precomp_tsig11_pi1 = commitments.tsig11 - v_1 * commitments.tsig11.rand_r - w_1 * commitments.tsig11.rand_s;
      auto precomp_g1branch0_pi1 = commitments.g1branch0 - v_1 * commitments.g1branch0.rand_r - w_1 * commitments.g1branch0.rand_s;
      auto precomp_fsig12_pi1 = commitments.fsig12 - v_1 * commitments.fsig12.rand_r - w_1 * commitments.fsig12.rand_s;
      auto precomp_pk_pi1 = commitments.pk - v_1 * commitments.pk.rand_r - w_1 * commitments.pk.rand_s;
      auto precomp_addr_pi1 = commitments.addr - v_1 * commitments.addr.rand_r - w_1 * commitments.addr.rand_s;
      proof.pi_v_1 = commitments.ppA11 * BN(-1) * commitments.fsig11.rand_r + commitments.ppUA11 * BN(1) * commitments.ssig11.rand_r + commitments.ppUA21 * BN(1) * commitments.ssig12.rand_r + commitments.ppVA21 * BN(1) * commitments.tsig12.rand_r + commitments.ppVA11 * BN(1) * commitments.tsig11.rand_r + commitments.vk11 * BN(1) * commitments.g1branch0.rand_r + commitments.ppA21 * BN(-1) * commitments.fsig12.rand_r + commitments.vk31 * BN(1) * commitments.pk.rand_r + commitments.vk21 * BN(1) * commitments.addr.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_fsig11_pi1 * BN(-1) * commitments.ppA11.rand_r + precomp_ssig11_pi1 * BN(1) * commitments.ppUA11.rand_r + precomp_ssig12_pi1 * BN(1) * commitments.ppUA21.rand_r + precomp_tsig12_pi1 * BN(1) * commitments.ppVA21.rand_r + precomp_tsig11_pi1 * BN(1) * commitments.ppVA11.rand_r + precomp_g1branch0_pi1 * BN(1) * commitments.vk11.rand_r + precomp_fsig12_pi1 * BN(-1) * commitments.ppA21.rand_r + precomp_pk_pi1 * BN(1) * commitments.vk31.rand_r + precomp_addr_pi1 * BN(1) * commitments.vk21.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.ppA11 * BN(-1) * commitments.fsig11.rand_s + commitments.ppUA11 * BN(1) * commitments.ssig11.rand_s + commitments.ppUA21 * BN(1) * commitments.ssig12.rand_s + commitments.ppVA21 * BN(1) * commitments.tsig12.rand_s + commitments.ppVA11 * BN(1) * commitments.tsig11.rand_s + commitments.vk11 * BN(1) * commitments.g1branch0.rand_s + commitments.ppA21 * BN(-1) * commitments.fsig12.rand_s + commitments.vk31 * BN(1) * commitments.pk.rand_s + commitments.vk21 * BN(1) * commitments.addr.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_fsig11_pi1 * BN(-1) * commitments.ppA11.rand_s + precomp_ssig11_pi1 * BN(1) * commitments.ppUA11.rand_s + precomp_ssig12_pi1 * BN(1) * commitments.ppUA21.rand_s + precomp_tsig12_pi1 * BN(1) * commitments.ppVA21.rand_s + precomp_tsig11_pi1 * BN(1) * commitments.ppVA11.rand_s + precomp_g1branch0_pi1 * BN(1) * commitments.vk11.rand_s + precomp_fsig12_pi1 * BN(-1) * commitments.ppA21.rand_s + precomp_pk_pi1 * BN(1) * commitments.vk31.rand_s + precomp_addr_pi1 * BN(1) * commitments.vk21.rand_s - v_1 * beta - w_1 * delta;

      return proof;
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

    auto prove_eq_e86(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppBtU11branch0_pi1 = commitments.ppBtU11branch0 - v_1 * commitments.ppBtU11branch0.rand_r;
      auto precomp_ppBtU11_pi1 = commitments.ppBtU11;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ppBtU11branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ppBtU11.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppBtU11branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ppBtU11_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ppBtU11branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ppBtU11.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppBtU11branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ppBtU11_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

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

    auto prove_eq_e89(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppBtV12_pi1 = commitments.ppBtV12;
      auto precomp_ppBtV12branch0_pi1 = commitments.ppBtV12branch0 - v_1 * commitments.ppBtV12branch0.rand_r;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.ppBtV12.rand_r + commitments.branch0 * BN(1) * commitments.ppBtV12branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppBtV12_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_ppBtV12branch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.ppBtV12.rand_s + commitments.branch0 * BN(1) * commitments.ppBtV12branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppBtV12_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_ppBtV12branch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

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
      auto precomp_g1branch0_pi1 = commitments.g1branch0 - v_1 * commitments.g1branch0.rand_r - w_1 * commitments.g1branch0.rand_s;
      auto precomp_pk_pi1 = commitments.pk - v_1 * commitments.pk.rand_r - w_1 * commitments.pk.rand_s;
      proof.pi_v_1 = commitments.siguser * BN(-1) * commitments.g1branch0.rand_r + commitments.h * BN(1) * commitments.pk.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1branch0_pi1 * BN(-1) * commitments.siguser.rand_r + precomp_pk_pi1 * BN(1) * commitments.h.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.siguser * BN(-1) * commitments.g1branch0.rand_s + commitments.h * BN(1) * commitments.pk.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1branch0_pi1 * BN(-1) * commitments.siguser.rand_s + precomp_pk_pi1 * BN(1) * commitments.h.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e88(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppBtV11branch0_pi1 = commitments.ppBtV11branch0 - v_1 * commitments.ppBtV11branch0.rand_r;
      auto precomp_ppBtV11_pi1 = commitments.ppBtV11;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ppBtV11branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ppBtV11.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppBtV11branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ppBtV11_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ppBtV11branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ppBtV11.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppBtV11branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ppBtV11_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e84(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppB11branch0_pi1 = commitments.ppB11branch0 - v_1 * commitments.ppB11branch0.rand_r;
      auto precomp_ppB11_pi1 = commitments.ppB11;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ppB11branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ppB11.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppB11branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ppB11_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ppB11branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ppB11.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppB11branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ppB11_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

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
      auto precomp_ct2branch0_pi1 = commitments.ct2branch0 - v_1 * commitments.ct2branch0.rand_r;
      auto precomp_ekbranch0_pi1 = commitments.ekbranch0 - v_1 * commitments.ekbranch0.rand_r;
      auto precomp_addr_pi1 = commitments.addr - v_1 * commitments.addr.rand_r - w_1 * commitments.addr.rand_s;
      proof.pi_v_1 = commitments.g2 * BN(1) * commitments.ct2branch0.rand_r + commitments.rinv * BN(1) * commitments.ekbranch0.rand_r + commitments.g2 * BN(-1) * commitments.addr.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ct2branch0_pi1 * BN(1) * commitments.g2.rand_r + precomp_ekbranch0_pi1 * BN(1) * commitments.rinv.rand_r + precomp_addr_pi1 * BN(-1) * commitments.g2.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.g2 * BN(1) * commitments.ct2branch0.rand_s + commitments.rinv * BN(1) * commitments.ekbranch0.rand_s + commitments.g2 * BN(-1) * commitments.addr.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ct2branch0_pi1 * BN(1) * commitments.g2.rand_s + precomp_ekbranch0_pi1 * BN(1) * commitments.rinv.rand_s + precomp_addr_pi1 * BN(-1) * commitments.g2.rand_s - v_1 * beta - w_1 * delta;

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
      auto precomp_ekbranch0_pi1 = commitments.ekbranch0 - v_1 * commitments.ekbranch0.rand_r;
      auto precomp_ek_pi1 = commitments.ek;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ekbranch0.rand_r + commitments.branch0 * BN(-1) * commitments.ek.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ekbranch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ek_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ekbranch0.rand_s + commitments.branch0 * BN(-1) * commitments.ek.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ekbranch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ek_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e05(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ssig11_pi1 = commitments.ssig11 - v_1 * commitments.ssig11.rand_r - w_1 * commitments.ssig11.rand_s;
      auto precomp_tsig11_pi1 = commitments.tsig11 - v_1 * commitments.tsig11.rand_r - w_1 * commitments.tsig11.rand_s;
      proof.pi_v_1 = commitments.fosig * BN(1) * commitments.ssig11.rand_r + commitments.g2 * BN(-1) * commitments.tsig11.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ssig11_pi1 * BN(1) * commitments.fosig.rand_r + precomp_tsig11_pi1 * BN(-1) * commitments.g2.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.fosig * BN(1) * commitments.ssig11.rand_s + commitments.g2 * BN(-1) * commitments.tsig11.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ssig11_pi1 * BN(1) * commitments.fosig.rand_s + precomp_tsig11_pi1 * BN(-1) * commitments.g2.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e85(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppB21_pi1 = commitments.ppB21;
      auto precomp_ppB21branch0_pi1 = commitments.ppB21branch0 - v_1 * commitments.ppB21branch0.rand_r;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.ppB21.rand_r + commitments.branch0 * BN(1) * commitments.ppB21branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppB21_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_ppB21branch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.ppB21.rand_s + commitments.branch0 * BN(1) * commitments.ppB21branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppB21_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_ppB21branch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

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
      auto precomp_ct1branch0_pi1 = commitments.ct1branch0 - v_1 * commitments.ct1branch0.rand_r;
      auto precomp_ct1_pi1 = commitments.ct1;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ct1branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ct1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ct1branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ct1_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ct1branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ct1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ct1branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ct1_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e06(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_tsig12_pi1 = commitments.tsig12 - v_1 * commitments.tsig12.rand_r - w_1 * commitments.tsig12.rand_s;
      auto precomp_ssig12_pi1 = commitments.ssig12 - v_1 * commitments.ssig12.rand_r - w_1 * commitments.ssig12.rand_s;
      proof.pi_v_1 = commitments.g2 * BN(-1) * commitments.tsig12.rand_r + commitments.fosig * BN(1) * commitments.ssig12.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_tsig12_pi1 * BN(-1) * commitments.g2.rand_r + precomp_ssig12_pi1 * BN(1) * commitments.fosig.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.g2 * BN(-1) * commitments.tsig12.rand_s + commitments.fosig * BN(1) * commitments.ssig12.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_tsig12_pi1 * BN(-1) * commitments.g2.rand_s + precomp_ssig12_pi1 * BN(1) * commitments.fosig.rand_s - v_1 * beta - w_1 * delta;

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
      proof.pi_v_1 = commitments.zkSig * BN(-1) * commitments.g1branch1.rand_r + commitments.g2 * BN(1) * commitments.zkPKbranch1.rand_r + commitments.zkHash * BN(1) * commitments.g1branch1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1branch1_pi1 * BN(-1) * commitments.zkSig.rand_r + precomp_zkPKbranch1_pi1 * BN(1) * commitments.g2.rand_r + precomp_g1branch1_pi1 * BN(1) * commitments.zkHash.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.zkSig * BN(-1) * commitments.g1branch1.rand_s + commitments.g2 * BN(1) * commitments.zkPKbranch1.rand_s + commitments.zkHash * BN(1) * commitments.g1branch1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1branch1_pi1 * BN(-1) * commitments.zkSig.rand_s + precomp_zkPKbranch1_pi1 * BN(1) * commitments.g2.rand_s + precomp_g1branch1_pi1 * BN(1) * commitments.zkHash.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    auto prove_eq_e87(CRS const &crs, GS_Commitments const &commitments)
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
      auto precomp_ppBtU12branch0_pi1 = commitments.ppBtU12branch0 - v_1 * commitments.ppBtU12branch0.rand_r;
      auto precomp_ppBtU12_pi1 = commitments.ppBtU12;
      proof.pi_v_1 = commitments.branch0 * BN(1) * commitments.ppBtU12branch0.rand_r + commitments.branch0 * BN(-1) * commitments.ppBtU12.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_ppBtU12branch0_pi1 * BN(1) * commitments.branch0.rand_r + precomp_ppBtU12_pi1 * BN(-1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(1) * commitments.ppBtU12branch0.rand_s + commitments.branch0 * BN(-1) * commitments.ppBtU12.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_ppBtU12branch0_pi1 * BN(1) * commitments.branch0.rand_s + precomp_ppBtU12_pi1 * BN(-1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

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
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.g1.rand_r + commitments.g2 * BN(1) * commitments.g1.rand_r + commitments.branch1 * BN(-1) * commitments.g1.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_g1_pi1 * BN(1) * commitments.g2.rand_r + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.g1.rand_s + commitments.g2 * BN(1) * commitments.g1.rand_s + commitments.branch1 * BN(-1) * commitments.g1.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_g1_pi1 * BN(1) * commitments.g2.rand_s + precomp_g1_pi1 * BN(-1) * commitments.branch1.rand_s - v_1 * beta - w_1 * delta;

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
      auto precomp_g1_pi1 = commitments.g1;
      auto precomp_g1branch0_pi1 = commitments.g1branch0 - v_1 * commitments.g1branch0.rand_r - w_1 * commitments.g1branch0.rand_s;
      proof.pi_v_1 = commitments.branch0 * BN(-1) * commitments.g1.rand_r + commitments.branch0 * BN(1) * commitments.g1branch0.rand_r + v_2 * alpha + w_2 * beta;

      proof.pi_v_2 = precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_r + precomp_g1branch0_pi1 * BN(1) * commitments.branch0.rand_r - v_1 * alpha - w_1 * gamma;

      proof.pi_w_1 = commitments.branch0 * BN(-1) * commitments.g1.rand_s + commitments.branch0 * BN(1) * commitments.g1branch0.rand_s + v_2 * gamma + w_2 * delta;

      proof.pi_w_2 = precomp_g1_pi1 * BN(-1) * commitments.branch0.rand_s + precomp_g1branch0_pi1 * BN(1) * commitments.branch0.rand_s - v_1 * beta - w_1 * delta;

      return proof;
    }

    GS_Proof prove(CRS const &crs, GS_Input const &input)
    {
      GS_Proof proof;
      tots::OTS tots = tots::OTS(crs.H);
      proof.ots_pk = tots.get_public_key();

      auto pk = pool.push([&](int) -> auto
                          { proof.commitments.pk = commit(crs, input.pk); return 0; });
      auto rinv = pool.push([&](int) -> auto
                            { proof.commitments.rinv = commit(crs, input.rinv); return 0; });
      auto addr = pool.push([&](int) -> auto
                            { proof.commitments.addr = commit(crs, input.addr); return 0; });
      auto siguser = pool.push([&](int) -> auto
                               { proof.commitments.siguser = commit(crs, input.siguser); return 0; });
      auto tsig11 = pool.push([&](int) -> auto
                              { proof.commitments.tsig11 = commit(crs, input.tsig11); return 0; });
      auto tsig12 = pool.push([&](int) -> auto
                              { proof.commitments.tsig12 = commit(crs, input.tsig12); return 0; });
      auto ssig11 = pool.push([&](int) -> auto
                              { proof.commitments.ssig11 = commit(crs, input.ssig11); return 0; });
      auto ssig12 = pool.push([&](int) -> auto
                              { proof.commitments.ssig12 = commit(crs, input.ssig12); return 0; });
      auto fsig11 = pool.push([&](int) -> auto
                              { proof.commitments.fsig11 = commit(crs, input.fsig11); return 0; });
      auto fsig12 = pool.push([&](int) -> auto
                              { proof.commitments.fsig12 = commit(crs, input.fsig12); return 0; });
      auto fosig = pool.push([&](int) -> auto
                             { proof.commitments.fosig = commit(crs, input.fosig); return 0; });
      auto branch0 = pool.push([&](int) -> auto
                               { proof.commitments.branch0 = commit(crs, ComVarG2{G2::get_gen()}); return 0; });
      auto g1branch0 = pool.push([&](int) -> auto
                                 { proof.commitments.g1branch0 = commit(crs, ComVarG1{G1::get_gen()}); return 0; });
      auto ct1branch0 = pool.push([&](int) -> auto
                                  { proof.commitments.ct1branch0 = commit(crs, EncVarG1{input.ct1.value}); return 0; });
      auto ct2branch0 = pool.push([&](int) -> auto
                                  { proof.commitments.ct2branch0 = commit(crs, EncVarG1{input.ct2.value}); return 0; });
      auto ekbranch0 = pool.push([&](int) -> auto
                                 { proof.commitments.ekbranch0 = commit(crs, EncVarG1{input.ek.value}); return 0; });
      auto ppB11branch0 = pool.push([&](int) -> auto
                                    { proof.commitments.ppB11branch0 = commit(crs, EncVarG1{input.ppB11.value}); return 0; });
      auto ppB21branch0 = pool.push([&](int) -> auto
                                    { proof.commitments.ppB21branch0 = commit(crs, EncVarG1{input.ppB21.value}); return 0; });
      auto ppBtU11branch0 = pool.push([&](int) -> auto
                                      { proof.commitments.ppBtU11branch0 = commit(crs, EncVarG1{input.ppBtU11.value}); return 0; });
      auto ppBtU12branch0 = pool.push([&](int) -> auto
                                      { proof.commitments.ppBtU12branch0 = commit(crs, EncVarG1{input.ppBtU12.value}); return 0; });
      auto ppBtV11branch0 = pool.push([&](int) -> auto
                                      { proof.commitments.ppBtV11branch0 = commit(crs, EncVarG1{input.ppBtV11.value}); return 0; });
      auto ppBtV12branch0 = pool.push([&](int) -> auto
                                      { proof.commitments.ppBtV12branch0 = commit(crs, EncVarG1{input.ppBtV12.value}); return 0; });
      auto branch1 = pool.push([&](int) -> auto
                               { proof.commitments.branch1 = commit(crs, ComVarG2{G2::get_infty()}); return 0; });
      auto g1branch1 = pool.push([&](int) -> auto
                                 { proof.commitments.g1branch1 = commit(crs, ComVarG1{G1::get_infty()}); return 0; });
      auto zkPKbranch1 = pool.push([&](int) -> auto
                                   { proof.commitments.zkPKbranch1 = commit(crs, EncVarG1{G1::get_infty()}); return 0; });
      auto zkSig = pool.push([&](int) -> auto
                             { proof.commitments.zkSig = commit(crs, EncVarG2{G2::get_infty()}); return 0; });

      proof.commitments.g1 = commit(crs, input.g1);
      proof.commitments.g2 = commit(crs, input.g2);
      proof.commitments.ct1 = commit(crs, input.ct1);
      proof.commitments.ct2 = commit(crs, input.ct2);
      proof.commitments.ek = commit(crs, input.ek);
      proof.commitments.h = commit(crs, input.h);
      proof.commitments.ppVA11 = commit(crs, input.ppVA11);
      proof.commitments.ppVA21 = commit(crs, input.ppVA21);
      proof.commitments.ppUA11 = commit(crs, input.ppUA11);
      proof.commitments.ppUA21 = commit(crs, input.ppUA21);
      proof.commitments.vk11 = commit(crs, input.vk11);
      proof.commitments.vk21 = commit(crs, input.vk21);
      proof.commitments.vk31 = commit(crs, input.vk31);
      proof.commitments.ppA11 = commit(crs, input.ppA11);
      proof.commitments.ppA21 = commit(crs, input.ppA21);
      proof.commitments.ppBtU11 = commit(crs, input.ppBtU11);
      proof.commitments.ppBtV12 = commit(crs, input.ppBtV12);
      proof.commitments.ppBtV11 = commit(crs, input.ppBtV11);
      proof.commitments.ppB11 = commit(crs, input.ppB11);
      proof.commitments.ppB21 = commit(crs, input.ppB21);
      proof.commitments.ppBtU12 = commit(crs, input.ppBtU12);
      proof.commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
      proof.commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});

      pk.get();
      addr.get();
      rinv.get();
      siguser.get();
      tsig11.get();
      tsig12.get();
      ssig11.get();
      ssig12.get();
      fsig11.get();
      fsig12.get();
      fosig.get();
      branch0.get();
      g1branch0.get();
      ct1branch0.get();
      ct2branch0.get();
      ekbranch0.get();
      ppB11branch0.get();
      ppB21branch0.get();
      ppBtU11branch0.get();
      ppBtU12branch0.get();
      ppBtV11branch0.get();
      ppBtV12branch0.get();
      branch1.get();
      g1branch1.get();
      zkPKbranch1.get();
      zkSig.get();

      auto eq_e04 = pool.push([&](int) -> auto
                              { proof.eq_e04 = prove_eq_e04(crs, proof.commitments); return 0; });
      auto eq_e01 = pool.push([&](int) -> auto
                              { proof.eq_e01 = prove_eq_e01(crs, proof.commitments); return 0; });
      auto eq_e90 = pool.push([&](int) -> auto
                              { proof.eq_e90 = prove_eq_e90(crs, proof.commitments); return 0; });
      auto eq_e86 = pool.push([&](int) -> auto
                              { proof.eq_e86 = prove_eq_e86(crs, proof.commitments); return 0; });
      auto eq_e82 = pool.push([&](int) -> auto
                              { proof.eq_e82 = prove_eq_e82(crs, proof.commitments); return 0; });
      auto eq_e89 = pool.push([&](int) -> auto
                              { proof.eq_e89 = prove_eq_e89(crs, proof.commitments); return 0; });
      auto eq_e03 = pool.push([&](int) -> auto
                              { proof.eq_e03 = prove_eq_e03(crs, proof.commitments); return 0; });
      auto eq_e88 = pool.push([&](int) -> auto
                              { proof.eq_e88 = prove_eq_e88(crs, proof.commitments); return 0; });
      auto eq_e84 = pool.push([&](int) -> auto
                              { proof.eq_e84 = prove_eq_e84(crs, proof.commitments); return 0; });
      auto eq_e02 = pool.push([&](int) -> auto
                              { proof.eq_e02 = prove_eq_e02(crs, proof.commitments); return 0; });
      auto eq_e83 = pool.push([&](int) -> auto
                              { proof.eq_e83 = prove_eq_e83(crs, proof.commitments); return 0; });
      auto eq_e05 = pool.push([&](int) -> auto
                              { proof.eq_e05 = prove_eq_e05(crs, proof.commitments); return 0; });
      auto eq_e85 = pool.push([&](int) -> auto
                              { proof.eq_e85 = prove_eq_e85(crs, proof.commitments); return 0; });
      auto eq_e81 = pool.push([&](int) -> auto
                              { proof.eq_e81 = prove_eq_e81(crs, proof.commitments); return 0; });
      auto eq_e06 = pool.push([&](int) -> auto
                              { proof.eq_e06 = prove_eq_e06(crs, proof.commitments); return 0; });
      auto eq_e60 = pool.push([&](int) -> auto
                              { proof.eq_e60 = prove_eq_e60(crs, proof.commitments); return 0; });
      auto eq_e87 = pool.push([&](int) -> auto
                              { proof.eq_e87 = prove_eq_e87(crs, proof.commitments); return 0; });
      auto eq_e70 = pool.push([&](int) -> auto
                              { proof.eq_e70 = prove_eq_e70(crs, proof.commitments); return 0; });
      auto eq_e91 = pool.push([&](int) -> auto
                              { proof.eq_e91 = prove_eq_e91(crs, proof.commitments); return 0; });
      auto eq_e80 = pool.push([&](int) -> auto
                              { proof.eq_e80 = prove_eq_e80(crs, proof.commitments); return 0; });
      eq_e04.get();
      eq_e01.get();
      eq_e90.get();
      eq_e86.get();
      eq_e82.get();
      eq_e89.get();
      eq_e03.get();
      eq_e88.get();
      eq_e84.get();
      eq_e02.get();
      eq_e83.get();
      eq_e05.get();
      eq_e85.get();
      eq_e81.get();
      eq_e06.get();
      eq_e60.get();
      eq_e87.get();
      eq_e70.get();
      eq_e91.get();
      eq_e80.get();

      std::vector<uint8_t> buffer;
      Serializer serializer(buffer);
      proof.serialize_without_sig(serializer);
      std::vector<uint8_t> proof_hash = BilinearGroup::hash(buffer.data(), buffer.size());
      proof.ots_sig = tots.sign(proof_hash);
      return proof;
    }

  } // namespace zkp
} // namespace GS
