#include "crypto/proofs/prelude.hpp"
#include "crypto/bookkeeping_proofs/create_entry/verifier.h"
#include "crypto/schemes/tots/scheme.h"

namespace GS
{

    using namespace std;
    using namespace BilinearGroup;

    namespace zkp
    {

        bool verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input)
        {
            GS_Commitments commitments = proof.commitments;
            commitments.g1 = commit(crs, input.g1);
            commitments.g2 = commit(crs, input.g2);
            commitments.ct1 = commit(crs, input.ct1);
            commitments.ct2 = commit(crs, input.ct2);
            commitments.ek = commit(crs, input.ek);
            commitments.h = commit(crs, input.h);
            commitments.ppA11 = commit(crs, input.ppA11);
            commitments.ppA21 = commit(crs, input.ppA21);
            commitments.ppVA11 = commit(crs, input.ppVA11);
            commitments.ppVA21 = commit(crs, input.ppVA21);
            commitments.ppUA11 = commit(crs, input.ppUA11);
            commitments.ppUA21 = commit(crs, input.ppUA21);
            commitments.ppB11 = commit(crs, input.ppB11);
            commitments.ppB21 = commit(crs, input.ppB21);
            commitments.ppBtU11 = commit(crs, input.ppBtU11);
            commitments.ppBtU12 = commit(crs, input.ppBtU12);
            commitments.ppBtV11 = commit(crs, input.ppBtV11);
            commitments.ppBtV12 = commit(crs, input.ppBtV12);
            commitments.vk11 = commit(crs, input.vk11);
            commitments.vk21 = commit(crs, input.vk21);
            commitments.vk31 = commit(crs, input.vk31);
            commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
            commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});

            std::vector<uint8_t> buffer;
            Serializer serializer(buffer);
            proof.serialize_without_sig(serializer);
            std::vector<uint8_t> proof_hash = BilinearGroup::hash(buffer.data(), buffer.size());
            bool verified = tots::OTS::verify(proof_hash, proof.ots_sig, proof.ots_pk, crs.H);
            if (!verified)
            {
                std::cout << "OTS verification failed\n"
                          << std::endl;
                return false;
            }

            auto lhs_e04 = pool.push([&](int) -> auto
                                     { return commitments.fsig11 * BN(-1) * commitments.ppA11 + commitments.ssig11 * BN(1) * commitments.ppUA11 + commitments.ssig12 * BN(1) * commitments.ppUA21 + commitments.tsig12 * BN(1) * commitments.ppVA21 + commitments.tsig11 * BN(1) * commitments.ppVA11 + commitments.g1branch0 * BN(1) * commitments.vk11 + commitments.fsig12 * BN(-1) * commitments.ppA21 + commitments.pk * BN(1) * commitments.vk31 + commitments.addr * BN(1) * commitments.vk21; });
            auto lhs_e01 = pool.push([&](int) -> auto
                                     { return commitments.ct1branch0 * BN(1) * commitments.g2 + commitments.g1branch0 * BN(1) * commitments.rinv; });
            auto lhs_e90 = pool.push([&](int) -> auto
                                     { return commitments.g1branch1 * BN(1) * commitments.branch1 + commitments.g1 * BN(-1) * commitments.branch1; });
            auto lhs_e86 = pool.push([&](int) -> auto
                                     { return commitments.ppBtU11branch0 * BN(1) * commitments.branch0 + commitments.ppBtU11 * BN(-1) * commitments.branch0; });
            auto lhs_e82 = pool.push([&](int) -> auto
                                     { return commitments.ct2branch0 * BN(1) * commitments.branch0 + commitments.ct2 * BN(-1) * commitments.branch0; });
            auto lhs_e89 = pool.push([&](int) -> auto
                                     { return commitments.ppBtV12 * BN(-1) * commitments.branch0 + commitments.ppBtV12branch0 * BN(1) * commitments.branch0; });
            auto lhs_e03 = pool.push([&](int) -> auto
                                     { return commitments.g1branch0 * BN(-1) * commitments.siguser + commitments.pk * BN(1) * commitments.h; });
            auto lhs_e88 = pool.push([&](int) -> auto
                                     { return commitments.ppBtV11branch0 * BN(1) * commitments.branch0 + commitments.ppBtV11 * BN(-1) * commitments.branch0; });
            auto lhs_e84 = pool.push([&](int) -> auto
                                     { return commitments.ppB11branch0 * BN(1) * commitments.branch0 + commitments.ppB11 * BN(-1) * commitments.branch0; });
            auto lhs_e02 = pool.push([&](int) -> auto
                                     { return commitments.ct2branch0 * BN(1) * commitments.g2 + commitments.ekbranch0 * BN(1) * commitments.rinv + commitments.addr * BN(-1) * commitments.g2; });
            auto lhs_e83 = pool.push([&](int) -> auto
                                     { return commitments.ekbranch0 * BN(1) * commitments.branch0 + commitments.ek * BN(-1) * commitments.branch0; });
            auto lhs_e05 = pool.push([&](int) -> auto
                                     { return commitments.ssig11 * BN(1) * commitments.fosig + commitments.tsig11 * BN(-1) * commitments.g2; });
            auto lhs_e85 = pool.push([&](int) -> auto
                                     { return commitments.ppB21 * BN(-1) * commitments.branch0 + commitments.ppB21branch0 * BN(1) * commitments.branch0; });
            auto lhs_e81 = pool.push([&](int) -> auto
                                     { return commitments.ct1branch0 * BN(1) * commitments.branch0 + commitments.ct1 * BN(-1) * commitments.branch0; });
            auto lhs_e06 = pool.push([&](int) -> auto
                                     { return commitments.tsig12 * BN(-1) * commitments.g2 + commitments.ssig12 * BN(1) * commitments.fosig; });
            auto lhs_e60 = pool.push([&](int) -> auto
                                     { return commitments.g1branch1 * BN(-1) * commitments.zkSig + commitments.zkPKbranch1 * BN(1) * commitments.g2 + commitments.g1branch1 * BN(1) * commitments.zkHash; });
            auto lhs_e87 = pool.push([&](int) -> auto
                                     { return commitments.ppBtU12branch0 * BN(1) * commitments.branch0 + commitments.ppBtU12 * BN(-1) * commitments.branch0; });
            auto lhs_e70 = pool.push([&](int) -> auto
                                     { return commitments.g1 * BN(-1) * commitments.branch0 + commitments.g1 * BN(1) * commitments.g2 + commitments.g1 * BN(-1) * commitments.branch1; });
            auto lhs_e91 = pool.push([&](int) -> auto
                                     { return commitments.zkPKbranch1 * BN(1) * commitments.branch1 + commitments.zkPK * BN(-1) * commitments.branch1; });
            auto lhs_e80 = pool.push([&](int) -> auto
                                     { return commitments.g1 * BN(-1) * commitments.branch0 + commitments.g1branch0 * BN(1) * commitments.branch0; });

            auto rhs_e04 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e04.pi_v_1 + crs.w1 * proof.eq_e04.pi_w_1 + proof.eq_e04.pi_v_2 * crs.v2 + proof.eq_e04.pi_w_2 * crs.w2; });
            auto rhs_e01 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e01.pi_v_1 + crs.w1 * proof.eq_e01.pi_w_1 + proof.eq_e01.pi_v_2 * crs.v2 + proof.eq_e01.pi_w_2 * crs.w2; });
            auto rhs_e90 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e90.pi_v_1 + crs.w1 * proof.eq_e90.pi_w_1 + proof.eq_e90.pi_v_2 * crs.v2 + proof.eq_e90.pi_w_2 * crs.w2; });
            auto rhs_e86 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e86.pi_v_1 + crs.w1 * proof.eq_e86.pi_w_1 + proof.eq_e86.pi_v_2 * crs.v2 + proof.eq_e86.pi_w_2 * crs.w2; });
            auto rhs_e82 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e82.pi_v_1 + crs.w1 * proof.eq_e82.pi_w_1 + proof.eq_e82.pi_v_2 * crs.v2 + proof.eq_e82.pi_w_2 * crs.w2; });
            auto rhs_e89 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e89.pi_v_1 + crs.w1 * proof.eq_e89.pi_w_1 + proof.eq_e89.pi_v_2 * crs.v2 + proof.eq_e89.pi_w_2 * crs.w2; });
            auto rhs_e03 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e03.pi_v_1 + crs.w1 * proof.eq_e03.pi_w_1 + proof.eq_e03.pi_v_2 * crs.v2 + proof.eq_e03.pi_w_2 * crs.w2; });
            auto rhs_e88 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e88.pi_v_1 + crs.w1 * proof.eq_e88.pi_w_1 + proof.eq_e88.pi_v_2 * crs.v2 + proof.eq_e88.pi_w_2 * crs.w2; });
            auto rhs_e84 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e84.pi_v_1 + crs.w1 * proof.eq_e84.pi_w_1 + proof.eq_e84.pi_v_2 * crs.v2 + proof.eq_e84.pi_w_2 * crs.w2; });
            auto rhs_e02 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e02.pi_v_1 + crs.w1 * proof.eq_e02.pi_w_1 + proof.eq_e02.pi_v_2 * crs.v2 + proof.eq_e02.pi_w_2 * crs.w2; });
            auto rhs_e83 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e83.pi_v_1 + crs.w1 * proof.eq_e83.pi_w_1 + proof.eq_e83.pi_v_2 * crs.v2 + proof.eq_e83.pi_w_2 * crs.w2; });
            auto rhs_e05 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e05.pi_v_1 + crs.w1 * proof.eq_e05.pi_w_1 + proof.eq_e05.pi_v_2 * crs.v2 + proof.eq_e05.pi_w_2 * crs.w2; });
            auto rhs_e85 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e85.pi_v_1 + crs.w1 * proof.eq_e85.pi_w_1 + proof.eq_e85.pi_v_2 * crs.v2 + proof.eq_e85.pi_w_2 * crs.w2; });
            auto rhs_e81 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e81.pi_v_1 + crs.w1 * proof.eq_e81.pi_w_1 + proof.eq_e81.pi_v_2 * crs.v2 + proof.eq_e81.pi_w_2 * crs.w2; });
            auto rhs_e06 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e06.pi_v_1 + crs.w1 * proof.eq_e06.pi_w_1 + proof.eq_e06.pi_v_2 * crs.v2 + proof.eq_e06.pi_w_2 * crs.w2; });
            auto rhs_e60 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e60.pi_v_1 + crs.w1 * proof.eq_e60.pi_w_1 + proof.eq_e60.pi_v_2 * crs.v2 + proof.eq_e60.pi_w_2 * crs.w2; });
            auto rhs_e87 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e87.pi_v_1 + crs.w1 * proof.eq_e87.pi_w_1 + proof.eq_e87.pi_v_2 * crs.v2 + proof.eq_e87.pi_w_2 * crs.w2; });
            auto rhs_e70 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e70.pi_v_1 + crs.w1 * proof.eq_e70.pi_w_1 + proof.eq_e70.pi_v_2 * crs.v2 + proof.eq_e70.pi_w_2 * crs.w2; });
            auto rhs_e91 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e91.pi_v_1 + crs.w1 * proof.eq_e91.pi_w_1 + proof.eq_e91.pi_v_2 * crs.v2 + proof.eq_e91.pi_w_2 * crs.w2; });
            auto rhs_e80 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e80.pi_v_1 + crs.w1 * proof.eq_e80.pi_w_1 + proof.eq_e80.pi_v_2 * crs.v2 + proof.eq_e80.pi_w_2 * crs.w2; });

            auto res_e04 = (lhs_e04.get() == rhs_e04.get());
            auto res_e01 = (lhs_e01.get() == rhs_e01.get());
            auto res_e90 = (lhs_e90.get() == rhs_e90.get());
            auto res_e86 = (lhs_e86.get() == rhs_e86.get());
            auto res_e82 = (lhs_e82.get() == rhs_e82.get());
            auto res_e89 = (lhs_e89.get() == rhs_e89.get());
            auto res_e03 = (lhs_e03.get() == rhs_e03.get());
            auto res_e88 = (lhs_e88.get() == rhs_e88.get());
            auto res_e84 = (lhs_e84.get() == rhs_e84.get());
            auto res_e02 = (lhs_e02.get() == rhs_e02.get());
            auto res_e83 = (lhs_e83.get() == rhs_e83.get());
            auto res_e05 = (lhs_e05.get() == rhs_e05.get());
            auto res_e85 = (lhs_e85.get() == rhs_e85.get());
            auto res_e81 = (lhs_e81.get() == rhs_e81.get());
            auto res_e06 = (lhs_e06.get() == rhs_e06.get());
            auto res_e60 = (lhs_e60.get() == rhs_e60.get());
            auto res_e87 = (lhs_e87.get() == rhs_e87.get());
            auto res_e70 = (lhs_e70.get() == rhs_e70.get());
            auto res_e91 = (lhs_e91.get() == rhs_e91.get());
            auto res_e80 = (lhs_e80.get() == rhs_e80.get());
            return res_e04 && res_e01 && res_e90 && res_e86 && res_e82 && res_e89 && res_e03 && res_e88 && res_e84 && res_e02 && res_e83 && res_e05 && res_e85 && res_e81 && res_e06 && res_e60 && res_e87 && res_e70 && res_e91 && res_e80;
        }

        bool batch_verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input)
        {
            GS_Commitments commitments = proof.commitments;
            commitments.g1 = commit(crs, input.g1);
            commitments.g2 = commit(crs, input.g2);
            commitments.ct1 = commit(crs, input.ct1);
            commitments.ct2 = commit(crs, input.ct2);
            commitments.ek = commit(crs, input.ek);
            commitments.h = commit(crs, input.h);
            commitments.ppA11 = commit(crs, input.ppA11);
            commitments.ppA21 = commit(crs, input.ppA21);
            commitments.ppVA11 = commit(crs, input.ppVA11);
            commitments.ppVA21 = commit(crs, input.ppVA21);
            commitments.ppUA11 = commit(crs, input.ppUA11);
            commitments.ppUA21 = commit(crs, input.ppUA21);
            commitments.ppB11 = commit(crs, input.ppB11);
            commitments.ppB21 = commit(crs, input.ppB21);
            commitments.ppBtU11 = commit(crs, input.ppBtU11);
            commitments.ppBtU12 = commit(crs, input.ppBtU12);
            commitments.ppBtV11 = commit(crs, input.ppBtV11);
            commitments.ppBtV12 = commit(crs, input.ppBtV12);
            commitments.vk11 = commit(crs, input.vk11);
            commitments.vk21 = commit(crs, input.vk21);
            commitments.vk31 = commit(crs, input.vk31);
            commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
            commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});

            std::vector<uint8_t> buffer;
            Serializer serializer(buffer);
            proof.serialize_without_sig(serializer);
            std::vector<uint8_t> proof_hash = BilinearGroup::hash(buffer.data(), buffer.size());
            bool verified = tots::OTS::verify(proof_hash, proof.ots_sig, proof.ots_pk, crs.H);
            if (!verified)
            {
                std::cout << "OTS verification failed\n"
                          << std::endl;
                return false;
            }
            BN alpha_batch = BN::rand(GS::BATCH_SOUNDNESS_ERROR, true);
            BN beta_batch = BN::rand(GS::BATCH_SOUNDNESS_ERROR, true);
            auto batched_c_tsig11 = batch_c(commitments.tsig11, alpha_batch);
            auto batched_c_ppVA11 = batch_c(commitments.ppVA11, beta_batch);
            auto batched_c_tsig12 = batch_c(commitments.tsig12, alpha_batch);
            auto batched_c_ppVA21 = batch_c(commitments.ppVA21, beta_batch);
            auto batched_c_ssig11 = batch_c(commitments.ssig11, alpha_batch);
            auto batched_c_ppUA11 = batch_c(commitments.ppUA11, beta_batch);
            auto batched_c_ssig12 = batch_c(commitments.ssig12, alpha_batch);
            auto batched_c_ppUA21 = batch_c(commitments.ppUA21, beta_batch);
            auto batched_c_g1branch0 = batch_c(commitments.g1branch0, alpha_batch);
            auto batched_c_vk11 = batch_c(commitments.vk11, beta_batch);
            auto batched_c_addr = batch_c(commitments.addr, alpha_batch);
            auto batched_c_vk21 = batch_c(commitments.vk21, beta_batch);
            auto batched_c_pk = batch_c(commitments.pk, alpha_batch);
            auto batched_c_vk31 = batch_c(commitments.vk31, beta_batch);
            auto batched_c_fsig11 = batch_c(commitments.fsig11, alpha_batch);
            auto batched_c_ppA11 = batch_c(commitments.ppA11, beta_batch);
            auto batched_c_fsig12 = batch_c(commitments.fsig12, alpha_batch);
            auto batched_c_ppA21 = batch_c(commitments.ppA21, beta_batch);
            auto batched_c_ct1branch0 = batch_c(commitments.ct1branch0, alpha_batch);
            auto batched_c_g2 = batch_c(commitments.g2, beta_batch);
            auto batched_c_rinv = batch_c(commitments.rinv, beta_batch);
            auto batched_c_g1branch1 = batch_c(commitments.g1branch1, alpha_batch);
            auto batched_c_branch1 = batch_c(commitments.branch1, beta_batch);
            auto batched_c_g1 = batch_c(commitments.g1, alpha_batch);
            auto batched_c_ppBtU11branch0 = batch_c(commitments.ppBtU11branch0, alpha_batch);
            auto batched_c_branch0 = batch_c(commitments.branch0, beta_batch);
            auto batched_c_ppBtU11 = batch_c(commitments.ppBtU11, alpha_batch);
            auto batched_c_ct2branch0 = batch_c(commitments.ct2branch0, alpha_batch);
            auto batched_c_ct2 = batch_c(commitments.ct2, alpha_batch);
            auto batched_c_ppBtV12branch0 = batch_c(commitments.ppBtV12branch0, alpha_batch);
            auto batched_c_ppBtV12 = batch_c(commitments.ppBtV12, alpha_batch);
            auto batched_c_h = batch_c(commitments.h, beta_batch);
            auto batched_c_siguser = batch_c(commitments.siguser, beta_batch);
            auto batched_c_ppBtV11branch0 = batch_c(commitments.ppBtV11branch0, alpha_batch);
            auto batched_c_ppBtV11 = batch_c(commitments.ppBtV11, alpha_batch);
            auto batched_c_ppB11branch0 = batch_c(commitments.ppB11branch0, alpha_batch);
            auto batched_c_ppB11 = batch_c(commitments.ppB11, alpha_batch);
            auto batched_c_ekbranch0 = batch_c(commitments.ekbranch0, alpha_batch);
            auto batched_c_ek = batch_c(commitments.ek, alpha_batch);
            auto batched_c_fosig = batch_c(commitments.fosig, beta_batch);
            auto batched_c_ppB21branch0 = batch_c(commitments.ppB21branch0, alpha_batch);
            auto batched_c_ppB21 = batch_c(commitments.ppB21, alpha_batch);
            auto batched_c_ct1 = batch_c(commitments.ct1, alpha_batch);
            auto batched_c_zkPKbranch1 = batch_c(commitments.zkPKbranch1, alpha_batch);
            auto batched_c_zkHash = batch_c(commitments.zkHash, beta_batch);
            auto batched_c_zkSig = batch_c(commitments.zkSig, beta_batch);
            auto batched_c_ppBtU12branch0 = batch_c(commitments.ppBtU12branch0, alpha_batch);
            auto batched_c_ppBtU12 = batch_c(commitments.ppBtU12, alpha_batch);
            auto batched_c_zkPK = batch_c(commitments.zkPK, alpha_batch);
            auto lhs_e04 = pool.push([&](int) -> auto
                                     { return batched_c_fsig11 * BN(-1) * batched_c_ppA11 + batched_c_ssig11 * BN(1) * batched_c_ppUA11 + batched_c_ssig12 * BN(1) * batched_c_ppUA21 + batched_c_tsig12 * BN(1) * batched_c_ppVA21 + batched_c_tsig11 * BN(1) * batched_c_ppVA11 + batched_c_g1branch0 * BN(1) * batched_c_vk11 + batched_c_fsig12 * BN(-1) * batched_c_ppA21 + batched_c_pk * BN(1) * batched_c_vk31 + batched_c_addr * BN(1) * batched_c_vk21; });
            auto lhs_e01 = pool.push([&](int) -> auto
                                     { return batched_c_ct1branch0 * BN(1) * batched_c_g2 + batched_c_g1branch0 * BN(1) * batched_c_rinv; });
            auto lhs_e90 = pool.push([&](int) -> auto
                                     { return batched_c_g1branch1 * BN(1) * batched_c_branch1 + batched_c_g1 * BN(-1) * batched_c_branch1; });
            auto lhs_e86 = pool.push([&](int) -> auto
                                     { return batched_c_ppBtU11branch0 * BN(1) * batched_c_branch0 + batched_c_ppBtU11 * BN(-1) * batched_c_branch0; });
            auto lhs_e82 = pool.push([&](int) -> auto
                                     { return batched_c_ct2branch0 * BN(1) * batched_c_branch0 + batched_c_ct2 * BN(-1) * batched_c_branch0; });
            auto lhs_e89 = pool.push([&](int) -> auto
                                     { return batched_c_ppBtV12 * BN(-1) * batched_c_branch0 + batched_c_ppBtV12branch0 * BN(1) * batched_c_branch0; });
            auto lhs_e03 = pool.push([&](int) -> auto
                                     { return batched_c_g1branch0 * BN(-1) * batched_c_siguser + batched_c_pk * BN(1) * batched_c_h; });
            auto lhs_e88 = pool.push([&](int) -> auto
                                     { return batched_c_ppBtV11branch0 * BN(1) * batched_c_branch0 + batched_c_ppBtV11 * BN(-1) * batched_c_branch0; });
            auto lhs_e84 = pool.push([&](int) -> auto
                                     { return batched_c_ppB11branch0 * BN(1) * batched_c_branch0 + batched_c_ppB11 * BN(-1) * batched_c_branch0; });
            auto lhs_e02 = pool.push([&](int) -> auto
                                     { return batched_c_ct2branch0 * BN(1) * batched_c_g2 + batched_c_ekbranch0 * BN(1) * batched_c_rinv + batched_c_addr * BN(-1) * batched_c_g2; });
            auto lhs_e83 = pool.push([&](int) -> auto
                                     { return batched_c_ekbranch0 * BN(1) * batched_c_branch0 + batched_c_ek * BN(-1) * batched_c_branch0; });
            auto lhs_e05 = pool.push([&](int) -> auto
                                     { return batched_c_ssig11 * BN(1) * batched_c_fosig + batched_c_tsig11 * BN(-1) * batched_c_g2; });
            auto lhs_e85 = pool.push([&](int) -> auto
                                     { return batched_c_ppB21 * BN(-1) * batched_c_branch0 + batched_c_ppB21branch0 * BN(1) * batched_c_branch0; });
            auto lhs_e81 = pool.push([&](int) -> auto
                                     { return batched_c_ct1branch0 * BN(1) * batched_c_branch0 + batched_c_ct1 * BN(-1) * batched_c_branch0; });
            auto lhs_e06 = pool.push([&](int) -> auto
                                     { return batched_c_tsig12 * BN(-1) * batched_c_g2 + batched_c_ssig12 * BN(1) * batched_c_fosig; });
            auto lhs_e60 = pool.push([&](int) -> auto
                                     { return batched_c_g1branch1 * BN(-1) * batched_c_zkSig + batched_c_zkPKbranch1 * BN(1) * batched_c_g2 + batched_c_g1branch1 * BN(1) * batched_c_zkHash; });
            auto lhs_e87 = pool.push([&](int) -> auto
                                     { return batched_c_ppBtU12branch0 * BN(1) * batched_c_branch0 + batched_c_ppBtU12 * BN(-1) * batched_c_branch0; });
            auto lhs_e70 = pool.push([&](int) -> auto
                                     { return batched_c_g1 * BN(-1) * batched_c_branch0 + batched_c_g1 * BN(1) * batched_c_g2 + batched_c_g1 * BN(-1) * batched_c_branch1; });
            auto lhs_e91 = pool.push([&](int) -> auto
                                     { return batched_c_zkPKbranch1 * BN(1) * batched_c_branch1 + batched_c_zkPK * BN(-1) * batched_c_branch1; });
            auto lhs_e80 = pool.push([&](int) -> auto
                                     { return batched_c_g1 * BN(-1) * batched_c_branch0 + batched_c_g1branch0 * BN(1) * batched_c_branch0; });

            auto b_v_1 = (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * crs.v1)(0, 0);
            auto b_w_1 = (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * crs.w1)(0, 0);
            auto b_v_2 = (crs.v2 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_w_2 = (crs.w2 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);

            auto b_p_e04_v1 =
                (proof.eq_e04.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e04_w1 =
                (proof.eq_e04.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e04_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e04.pi_v_2)(0, 0);
            auto b_p_e04_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e04.pi_w_2)(0, 0);
            ;
            auto b_p_e01_v1 =
                (proof.eq_e01.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e01_w1 =
                (proof.eq_e01.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e01_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e01.pi_v_2)(0, 0);
            auto b_p_e01_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e01.pi_w_2)(0, 0);
            ;
            auto b_p_e90_v1 =
                (proof.eq_e90.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e90_w1 =
                (proof.eq_e90.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e90_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e90.pi_v_2)(0, 0);
            auto b_p_e90_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e90.pi_w_2)(0, 0);
            ;
            auto b_p_e86_v1 =
                (proof.eq_e86.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e86_w1 =
                (proof.eq_e86.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e86_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e86.pi_v_2)(0, 0);
            auto b_p_e86_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e86.pi_w_2)(0, 0);
            ;
            auto b_p_e82_v1 =
                (proof.eq_e82.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e82_w1 =
                (proof.eq_e82.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e82_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e82.pi_v_2)(0, 0);
            auto b_p_e82_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e82.pi_w_2)(0, 0);
            ;
            auto b_p_e89_v1 =
                (proof.eq_e89.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e89_w1 =
                (proof.eq_e89.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e89_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e89.pi_v_2)(0, 0);
            auto b_p_e89_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e89.pi_w_2)(0, 0);
            ;
            auto b_p_e03_v1 =
                (proof.eq_e03.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e03_w1 =
                (proof.eq_e03.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e03_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e03.pi_v_2)(0, 0);
            auto b_p_e03_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e03.pi_w_2)(0, 0);
            ;
            auto b_p_e88_v1 =
                (proof.eq_e88.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e88_w1 =
                (proof.eq_e88.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e88_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e88.pi_v_2)(0, 0);
            auto b_p_e88_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e88.pi_w_2)(0, 0);
            ;
            auto b_p_e84_v1 =
                (proof.eq_e84.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e84_w1 =
                (proof.eq_e84.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e84_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e84.pi_v_2)(0, 0);
            auto b_p_e84_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e84.pi_w_2)(0, 0);
            ;
            auto b_p_e02_v1 =
                (proof.eq_e02.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e02_w1 =
                (proof.eq_e02.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e02_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e02.pi_v_2)(0, 0);
            auto b_p_e02_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e02.pi_w_2)(0, 0);
            ;
            auto b_p_e83_v1 =
                (proof.eq_e83.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e83_w1 =
                (proof.eq_e83.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e83_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e83.pi_v_2)(0, 0);
            auto b_p_e83_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e83.pi_w_2)(0, 0);
            ;
            auto b_p_e05_v1 =
                (proof.eq_e05.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e05_w1 =
                (proof.eq_e05.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e05_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e05.pi_v_2)(0, 0);
            auto b_p_e05_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e05.pi_w_2)(0, 0);
            ;
            auto b_p_e85_v1 =
                (proof.eq_e85.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e85_w1 =
                (proof.eq_e85.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e85_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e85.pi_v_2)(0, 0);
            auto b_p_e85_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e85.pi_w_2)(0, 0);
            ;
            auto b_p_e81_v1 =
                (proof.eq_e81.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e81_w1 =
                (proof.eq_e81.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e81_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e81.pi_v_2)(0, 0);
            auto b_p_e81_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e81.pi_w_2)(0, 0);
            ;
            auto b_p_e06_v1 =
                (proof.eq_e06.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e06_w1 =
                (proof.eq_e06.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e06_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e06.pi_v_2)(0, 0);
            auto b_p_e06_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e06.pi_w_2)(0, 0);
            ;
            auto b_p_e60_v1 =
                (proof.eq_e60.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e60_w1 =
                (proof.eq_e60.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e60_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e60.pi_v_2)(0, 0);
            auto b_p_e60_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e60.pi_w_2)(0, 0);
            ;
            auto b_p_e87_v1 =
                (proof.eq_e87.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e87_w1 =
                (proof.eq_e87.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e87_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e87.pi_v_2)(0, 0);
            auto b_p_e87_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e87.pi_w_2)(0, 0);
            ;
            auto b_p_e70_v1 =
                (proof.eq_e70.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e70_w1 =
                (proof.eq_e70.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e70_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e70.pi_v_2)(0, 0);
            auto b_p_e70_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e70.pi_w_2)(0, 0);
            ;
            auto b_p_e91_v1 =
                (proof.eq_e91.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e91_w1 =
                (proof.eq_e91.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e91_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e91.pi_v_2)(0, 0);
            auto b_p_e91_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e91.pi_w_2)(0, 0);
            ;
            auto b_p_e80_v1 =
                (proof.eq_e80.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e80_w1 =
                (proof.eq_e80.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e80_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e80.pi_v_2)(0, 0);
            auto b_p_e80_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e80.pi_w_2)(0, 0);

            auto rhs_e04 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e04_v1 + b_w_1 * b_p_e04_w1 + b_p_e04_v2 * b_v_2 + b_p_e04_w2 * b_w_2;; });
            auto rhs_e01 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e01_v1 + b_w_1 * b_p_e01_w1 + b_p_e01_v2 * b_v_2 + b_p_e01_w2 * b_w_2;; });
            auto rhs_e90 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e90_v1 + b_w_1 * b_p_e90_w1 + b_p_e90_v2 * b_v_2 + b_p_e90_w2 * b_w_2;; });
            auto rhs_e86 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e86_v1 + b_w_1 * b_p_e86_w1 + b_p_e86_v2 * b_v_2 + b_p_e86_w2 * b_w_2;; });
            auto rhs_e82 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e82_v1 + b_w_1 * b_p_e82_w1 + b_p_e82_v2 * b_v_2 + b_p_e82_w2 * b_w_2;; });
            auto rhs_e89 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e89_v1 + b_w_1 * b_p_e89_w1 + b_p_e89_v2 * b_v_2 + b_p_e89_w2 * b_w_2;; });
            auto rhs_e03 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e03_v1 + b_w_1 * b_p_e03_w1 + b_p_e03_v2 * b_v_2 + b_p_e03_w2 * b_w_2;; });
            auto rhs_e88 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e88_v1 + b_w_1 * b_p_e88_w1 + b_p_e88_v2 * b_v_2 + b_p_e88_w2 * b_w_2;; });
            auto rhs_e84 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e84_v1 + b_w_1 * b_p_e84_w1 + b_p_e84_v2 * b_v_2 + b_p_e84_w2 * b_w_2;; });
            auto rhs_e02 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e02_v1 + b_w_1 * b_p_e02_w1 + b_p_e02_v2 * b_v_2 + b_p_e02_w2 * b_w_2;; });
            auto rhs_e83 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e83_v1 + b_w_1 * b_p_e83_w1 + b_p_e83_v2 * b_v_2 + b_p_e83_w2 * b_w_2;; });
            auto rhs_e05 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e05_v1 + b_w_1 * b_p_e05_w1 + b_p_e05_v2 * b_v_2 + b_p_e05_w2 * b_w_2;; });
            auto rhs_e85 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e85_v1 + b_w_1 * b_p_e85_w1 + b_p_e85_v2 * b_v_2 + b_p_e85_w2 * b_w_2;; });
            auto rhs_e81 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e81_v1 + b_w_1 * b_p_e81_w1 + b_p_e81_v2 * b_v_2 + b_p_e81_w2 * b_w_2;; });
            auto rhs_e06 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e06_v1 + b_w_1 * b_p_e06_w1 + b_p_e06_v2 * b_v_2 + b_p_e06_w2 * b_w_2;; });
            auto rhs_e60 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e60_v1 + b_w_1 * b_p_e60_w1 + b_p_e60_v2 * b_v_2 + b_p_e60_w2 * b_w_2;; });
            auto rhs_e87 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e87_v1 + b_w_1 * b_p_e87_w1 + b_p_e87_v2 * b_v_2 + b_p_e87_w2 * b_w_2;; });
            auto rhs_e70 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e70_v1 + b_w_1 * b_p_e70_w1 + b_p_e70_v2 * b_v_2 + b_p_e70_w2 * b_w_2;; });
            auto rhs_e91 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e91_v1 + b_w_1 * b_p_e91_w1 + b_p_e91_v2 * b_v_2 + b_p_e91_w2 * b_w_2;; });
            auto rhs_e80 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e80_v1 + b_w_1 * b_p_e80_w1 + b_p_e80_v2 * b_v_2 + b_p_e80_w2 * b_w_2;; });

            auto res_e04 = (lhs_e04.get() == rhs_e04.get());
            auto res_e01 = (lhs_e01.get() == rhs_e01.get());
            auto res_e90 = (lhs_e90.get() == rhs_e90.get());
            auto res_e86 = (lhs_e86.get() == rhs_e86.get());
            auto res_e82 = (lhs_e82.get() == rhs_e82.get());
            auto res_e89 = (lhs_e89.get() == rhs_e89.get());
            auto res_e03 = (lhs_e03.get() == rhs_e03.get());
            auto res_e88 = (lhs_e88.get() == rhs_e88.get());
            auto res_e84 = (lhs_e84.get() == rhs_e84.get());
            auto res_e02 = (lhs_e02.get() == rhs_e02.get());
            auto res_e83 = (lhs_e83.get() == rhs_e83.get());
            auto res_e05 = (lhs_e05.get() == rhs_e05.get());
            auto res_e85 = (lhs_e85.get() == rhs_e85.get());
            auto res_e81 = (lhs_e81.get() == rhs_e81.get());
            auto res_e06 = (lhs_e06.get() == rhs_e06.get());
            auto res_e60 = (lhs_e60.get() == rhs_e60.get());
            auto res_e87 = (lhs_e87.get() == rhs_e87.get());
            auto res_e70 = (lhs_e70.get() == rhs_e70.get());
            auto res_e91 = (lhs_e91.get() == rhs_e91.get());
            auto res_e80 = (lhs_e80.get() == rhs_e80.get());
            return res_e04 && res_e01 && res_e90 && res_e86 && res_e82 && res_e89 && res_e03 && res_e88 && res_e84 && res_e02 && res_e83 && res_e05 && res_e85 && res_e81 && res_e06 && res_e60 && res_e87 && res_e70 && res_e91 && res_e80;
        }

    } // namespace zkp
} // namespace GS
