#include "crypto/proofs/prelude.hpp"
#include "crypto/bookkeeping_proofs/prove_entry/verifier.h"
#include "crypto/schemes/tots/scheme.h"

namespace GS
{

    using namespace std;
    using namespace BilinearGroup;

    namespace prove_entry
    {

        bool verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input)
        {
            GS_Commitments commitments = proof.commitments;
            commitments.g2 = commit(crs, input.g2);
            commitments.ct2 = commit(crs, input.ct2);
            commitments.pk = commit(crs, input.pk);
            commitments.ct1 = commit(crs, input.ct1);
            commitments.g1 = commit(crs, input.g1);
            commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
            commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});
            commitments.addr = commit(crs, input.addr);
            commitments.ek = commit(crs, input.ek);
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
            auto lhs_e01 = pool.push([&](int) -> auto
                                     { return commitments.ct1branch0 * BN(1) * commitments.g2 + commitments.g1branch0 * BN(1) * commitments.rinv; });
            auto lhs_e82 = pool.push([&](int) -> auto
                                     { return commitments.ct2branch0 * BN(1) * commitments.branch0 + commitments.ct2 * BN(-1) * commitments.branch0; });
            auto lhs_e91 = pool.push([&](int) -> auto
                                     { return commitments.zkPKbranch1 * BN(1) * commitments.branch1 + commitments.zkPK * BN(-1) * commitments.branch1; });
            auto lhs_e80 = pool.push([&](int) -> auto
                                     { return commitments.pk * BN(-1) * commitments.branch0 + commitments.pkbranch0 * BN(1) * commitments.branch0; });
            auto lhs_e81 = pool.push([&](int) -> auto
                                     { return commitments.ct1 * BN(-1) * commitments.branch0 + commitments.ct1branch0 * BN(1) * commitments.branch0; });
            auto lhs_e70 = pool.push([&](int) -> auto
                                     { return commitments.g1 * BN(1) * commitments.g2 + commitments.g1 * BN(-1) * commitments.branch0 + commitments.g1 * BN(-1) * commitments.branch1; });
            auto lhs_e03 = pool.push([&](int) -> auto
                                     { return commitments.pkbranch0 * BN(1) * commitments.g2 + commitments.g1branch0 * BN(1) * commitments.sk; });
            auto lhs_e90 = pool.push([&](int) -> auto
                                     { return commitments.g1branch1 * BN(1) * commitments.branch1 + commitments.g1 * BN(-1) * commitments.branch1; });
            auto lhs_e60 = pool.push([&](int) -> auto
                                     { return commitments.g1branch1 * BN(1) * commitments.zkHash + commitments.g1branch1 * BN(-1) * commitments.zkSig + commitments.zkPKbranch1 * BN(1) * commitments.g2; });
            auto lhs_e02 = pool.push([&](int) -> auto
                                     { return commitments.ekbranch0 * BN(1) * commitments.rinv + commitments.addr * BN(-1) * commitments.g2 + commitments.ct2branch0 * BN(1) * commitments.g2; });
            auto lhs_e83 = pool.push([&](int) -> auto
                                     { return commitments.ek * BN(-1) * commitments.branch0 + commitments.ekbranch0 * BN(1) * commitments.branch0; });

            auto rhs_e01 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e01.pi_v_1 + crs.w1 * proof.eq_e01.pi_w_1 + proof.eq_e01.pi_v_2 * crs.v2 + proof.eq_e01.pi_w_2 * crs.w2; });
            ;
            auto rhs_e82 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e82.pi_v_1 + crs.w1 * proof.eq_e82.pi_w_1 + proof.eq_e82.pi_v_2 * crs.v2 + proof.eq_e82.pi_w_2 * crs.w2; });
            ;
            auto rhs_e91 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e91.pi_v_1 + crs.w1 * proof.eq_e91.pi_w_1 + proof.eq_e91.pi_v_2 * crs.v2 + proof.eq_e91.pi_w_2 * crs.w2; });
            ;
            auto rhs_e80 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e80.pi_v_1 + crs.w1 * proof.eq_e80.pi_w_1 + proof.eq_e80.pi_v_2 * crs.v2 + proof.eq_e80.pi_w_2 * crs.w2; });
            ;
            auto rhs_e81 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e81.pi_v_1 + crs.w1 * proof.eq_e81.pi_w_1 + proof.eq_e81.pi_v_2 * crs.v2 + proof.eq_e81.pi_w_2 * crs.w2; });
            ;
            auto rhs_e70 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e70.pi_v_1 + crs.w1 * proof.eq_e70.pi_w_1 + proof.eq_e70.pi_v_2 * crs.v2 + proof.eq_e70.pi_w_2 * crs.w2; });
            ;
            auto rhs_e03 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e03.pi_v_1 + crs.w1 * proof.eq_e03.pi_w_1 + proof.eq_e03.pi_v_2 * crs.v2 + proof.eq_e03.pi_w_2 * crs.w2; });
            ;
            auto rhs_e90 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e90.pi_v_1 + crs.w1 * proof.eq_e90.pi_w_1 + proof.eq_e90.pi_v_2 * crs.v2 + proof.eq_e90.pi_w_2 * crs.w2; });
            ;
            auto rhs_e60 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e60.pi_v_1 + crs.w1 * proof.eq_e60.pi_w_1 + proof.eq_e60.pi_v_2 * crs.v2 + proof.eq_e60.pi_w_2 * crs.w2; });
            ;
            auto rhs_e02 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e02.pi_v_1 + crs.w1 * proof.eq_e02.pi_w_1 + proof.eq_e02.pi_v_2 * crs.v2 + proof.eq_e02.pi_w_2 * crs.w2; });
            ;
            auto rhs_e83 = pool.push([&](int) -> auto
                                     { return crs.v1 * proof.eq_e83.pi_v_1 + crs.w1 * proof.eq_e83.pi_w_1 + proof.eq_e83.pi_v_2 * crs.v2 + proof.eq_e83.pi_w_2 * crs.w2; });
            ;

            auto res_e01 = (lhs_e01.get() == rhs_e01.get());
            auto res_e82 = (lhs_e82.get() == rhs_e82.get());
            auto res_e91 = (lhs_e91.get() == rhs_e91.get());
            auto res_e80 = (lhs_e80.get() == rhs_e80.get());
            auto res_e81 = (lhs_e81.get() == rhs_e81.get());
            auto res_e70 = (lhs_e70.get() == rhs_e70.get());
            auto res_e03 = (lhs_e03.get() == rhs_e03.get());
            auto res_e90 = (lhs_e90.get() == rhs_e90.get());
            auto res_e60 = (lhs_e60.get() == rhs_e60.get());
            auto res_e02 = (lhs_e02.get() == rhs_e02.get());
            auto res_e83 = (lhs_e83.get() == rhs_e83.get());
            return res_e01 && res_e82 && res_e91 && res_e80 && res_e81 && res_e70 && res_e03 && res_e90 && res_e60 && res_e02 && res_e83;
        }

        bool batch_verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input)
        {
            GS_Commitments commitments = proof.commitments;
            commitments.g2 = commit(crs, input.g2);
            commitments.ct2 = commit(crs, input.ct2);
            commitments.pk = commit(crs, input.pk);
            commitments.ct1 = commit(crs, input.ct1);
            commitments.g1 = commit(crs, input.g1);
            commitments.zkHash = commit(crs, PubVarG2{tots::OTS::hash_public_key(proof.ots_pk)});
            commitments.zkPK = commit(crs, PubVarG1{crs.bls_pk});
            commitments.addr = commit(crs, input.addr);
            commitments.ek = commit(crs, input.ek);
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
            auto batched_c_ct1branch0 = batch_c(commitments.ct1branch0, alpha_batch);
            auto batched_c_g2 = batch_c(commitments.g2, beta_batch);
            auto batched_c_g1branch0 = batch_c(commitments.g1branch0, alpha_batch);
            auto batched_c_rinv = batch_c(commitments.rinv, beta_batch);
            auto batched_c_ct2branch0 = batch_c(commitments.ct2branch0, alpha_batch);
            auto batched_c_branch0 = batch_c(commitments.branch0, beta_batch);
            auto batched_c_ct2 = batch_c(commitments.ct2, alpha_batch);
            auto batched_c_zkPKbranch1 = batch_c(commitments.zkPKbranch1, alpha_batch);
            auto batched_c_branch1 = batch_c(commitments.branch1, beta_batch);
            auto batched_c_zkPK = batch_c(commitments.zkPK, alpha_batch);
            auto batched_c_pkbranch0 = batch_c(commitments.pkbranch0, alpha_batch);
            auto batched_c_pk = batch_c(commitments.pk, alpha_batch);
            auto batched_c_ct1 = batch_c(commitments.ct1, alpha_batch);
            auto batched_c_g1 = batch_c(commitments.g1, alpha_batch);
            auto batched_c_sk = batch_c(commitments.sk, beta_batch);
            auto batched_c_g1branch1 = batch_c(commitments.g1branch1, alpha_batch);
            auto batched_c_zkHash = batch_c(commitments.zkHash, beta_batch);
            auto batched_c_zkSig = batch_c(commitments.zkSig, beta_batch);
            auto batched_c_ekbranch0 = batch_c(commitments.ekbranch0, alpha_batch);
            auto batched_c_addr = batch_c(commitments.addr, alpha_batch);
            auto batched_c_ek = batch_c(commitments.ek, alpha_batch);
            auto lhs_e01 = pool.push([&](int) -> auto
                                     { return batched_c_ct1branch0 * BN(1) * batched_c_g2 + batched_c_g1branch0 * BN(1) * batched_c_rinv; });
            auto lhs_e82 = pool.push([&](int) -> auto
                                     { return batched_c_ct2branch0 * BN(1) * batched_c_branch0 + batched_c_ct2 * BN(-1) * batched_c_branch0; });
            auto lhs_e91 = pool.push([&](int) -> auto
                                     { return batched_c_zkPKbranch1 * BN(1) * batched_c_branch1 + batched_c_zkPK * BN(-1) * batched_c_branch1; });
            auto lhs_e80 = pool.push([&](int) -> auto
                                     { return batched_c_pk * BN(-1) * batched_c_branch0 + batched_c_pkbranch0 * BN(1) * batched_c_branch0; });
            auto lhs_e81 = pool.push([&](int) -> auto
                                     { return batched_c_ct1 * BN(-1) * batched_c_branch0 + batched_c_ct1branch0 * BN(1) * batched_c_branch0; });
            auto lhs_e70 = pool.push([&](int) -> auto
                                     { return batched_c_g1 * BN(1) * batched_c_g2 + batched_c_g1 * BN(-1) * batched_c_branch0 + batched_c_g1 * BN(-1) * batched_c_branch1; });
            auto lhs_e03 = pool.push([&](int) -> auto
                                     { return batched_c_pkbranch0 * BN(1) * batched_c_g2 + batched_c_g1branch0 * BN(1) * batched_c_sk; });
            auto lhs_e90 = pool.push([&](int) -> auto
                                     { return batched_c_g1branch1 * BN(1) * batched_c_branch1 + batched_c_g1 * BN(-1) * batched_c_branch1; });
            auto lhs_e60 = pool.push([&](int) -> auto
                                     { return batched_c_g1branch1 * BN(1) * batched_c_zkHash + batched_c_g1branch1 * BN(-1) * batched_c_zkSig + batched_c_zkPKbranch1 * BN(1) * batched_c_g2; });
            auto lhs_e02 = pool.push([&](int) -> auto
                                     { return batched_c_ekbranch0 * BN(1) * batched_c_rinv + batched_c_addr * BN(-1) * batched_c_g2 + batched_c_ct2branch0 * BN(1) * batched_c_g2; });
            auto lhs_e83 = pool.push([&](int) -> auto
                                     { return batched_c_ek * BN(-1) * batched_c_branch0 + batched_c_ekbranch0 * BN(1) * batched_c_branch0; });

            auto b_v_1 = (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * crs.v1)(0, 0);
            auto b_w_1 = (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * crs.w1)(0, 0);
            auto b_v_2 = (crs.v2 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_w_2 = (crs.w2 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);

            auto b_p_e01_v1 =
                (proof.eq_e01.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e01_w1 =
                (proof.eq_e01.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e01_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e01.pi_v_2)(0, 0);
            auto b_p_e01_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e01.pi_w_2)(0, 0);
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
            auto b_p_e70_v1 =
                (proof.eq_e70.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e70_w1 =
                (proof.eq_e70.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e70_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e70.pi_v_2)(0, 0);
            auto b_p_e70_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e70.pi_w_2)(0, 0);
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
            auto b_p_e90_v1 =
                (proof.eq_e90.pi_v_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e90_w1 =
                (proof.eq_e90.pi_w_1 * TMatrix<2, 1, BN>{beta_batch, BN(1)})(0, 0);
            auto b_p_e90_v2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e90.pi_v_2)(0, 0);
            auto b_p_e90_w2 =
                (TMatrix<1, 2, BN>{alpha_batch, BN(1)} * proof.eq_e90.pi_w_2)(0, 0);
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

            auto rhs_e01 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e01_v1 + b_w_1 * b_p_e01_w1 + b_p_e01_v2 * b_v_2 + b_p_e01_w2 * b_w_2;; });
            auto rhs_e82 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e82_v1 + b_w_1 * b_p_e82_w1 + b_p_e82_v2 * b_v_2 + b_p_e82_w2 * b_w_2;; });
            auto rhs_e91 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e91_v1 + b_w_1 * b_p_e91_w1 + b_p_e91_v2 * b_v_2 + b_p_e91_w2 * b_w_2;; });
            auto rhs_e80 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e80_v1 + b_w_1 * b_p_e80_w1 + b_p_e80_v2 * b_v_2 + b_p_e80_w2 * b_w_2;; });
            auto rhs_e81 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e81_v1 + b_w_1 * b_p_e81_w1 + b_p_e81_v2 * b_v_2 + b_p_e81_w2 * b_w_2;; });
            auto rhs_e70 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e70_v1 + b_w_1 * b_p_e70_w1 + b_p_e70_v2 * b_v_2 + b_p_e70_w2 * b_w_2;; });
            auto rhs_e03 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e03_v1 + b_w_1 * b_p_e03_w1 + b_p_e03_v2 * b_v_2 + b_p_e03_w2 * b_w_2;; });
            auto rhs_e90 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e90_v1 + b_w_1 * b_p_e90_w1 + b_p_e90_v2 * b_v_2 + b_p_e90_w2 * b_w_2;; });
            auto rhs_e60 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e60_v1 + b_w_1 * b_p_e60_w1 + b_p_e60_v2 * b_v_2 + b_p_e60_w2 * b_w_2;; });
            auto rhs_e02 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e02_v1 + b_w_1 * b_p_e02_w1 + b_p_e02_v2 * b_v_2 + b_p_e02_w2 * b_w_2;; });
            auto rhs_e83 = pool.push([&](int) -> auto
                                     { return b_v_1 * b_p_e83_v1 + b_w_1 * b_p_e83_w1 + b_p_e83_v2 * b_v_2 + b_p_e83_w2 * b_w_2;; });

            auto res_e01 = (lhs_e01.get() == rhs_e01.get());
            auto res_e82 = (lhs_e82.get() == rhs_e82.get());
            auto res_e91 = (lhs_e91.get() == rhs_e91.get());
            auto res_e80 = (lhs_e80.get() == rhs_e80.get());
            auto res_e81 = (lhs_e81.get() == rhs_e81.get());
            auto res_e70 = (lhs_e70.get() == rhs_e70.get());
            auto res_e03 = (lhs_e03.get() == rhs_e03.get());
            auto res_e90 = (lhs_e90.get() == rhs_e90.get());
            auto res_e60 = (lhs_e60.get() == rhs_e60.get());
            auto res_e02 = (lhs_e02.get() == rhs_e02.get());
            auto res_e83 = (lhs_e83.get() == rhs_e83.get());
            std::cout << "e01: " << res_e01 << std::endl;
            std::cout << "e82: " << res_e82 << std::endl;
            std::cout << "e91: " << res_e91 << std::endl;
            std::cout << "e80: " << res_e80 << std::endl;
            std::cout << "e81: " << res_e81 << std::endl;
            std::cout << "e70: " << res_e70 << std::endl;
            std::cout << "e03: " << res_e03 << std::endl;
            std::cout << "e90: " << res_e90 << std::endl;
            std::cout << "e60: " << res_e60 << std::endl;
            std::cout << "e02: " << res_e02 << std::endl;
            std::cout << "e83: " << res_e83 << std::endl;

            return res_e01 && res_e82 && res_e91 && res_e80 && res_e81 && res_e70 && res_e03 && res_e90 && res_e60 && res_e02 && res_e83;
        }

    } // namespace prove_entry
} // namespace GS
