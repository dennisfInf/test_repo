#pragma once
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/tots/scheme.h"

namespace GS
{
  using namespace BilinearGroup;
  namespace zkp
  {

    struct GS_Commitments
    {
      GenCommitG1 g1;
      GenCommitG2 g2;
      PubCommitG1 ct1;
      PubCommitG1 ct2;
      PubCommitG1 ek;
      PubCommitG2 h;
      PubCommitG2 ppA11;
      PubCommitG2 ppA21;
      PubCommitG1 ppB11;
      PubCommitG1 ppB21;
      PubCommitG1 ppBtU11;
      PubCommitG1 ppBtU12;
      PubCommitG1 ppBtV11;
      PubCommitG1 ppBtV12;
      PubCommitG2 ppUA11;
      PubCommitG2 ppUA21;
      PubCommitG2 ppVA11;
      PubCommitG2 ppVA21;
      PubCommitG2 vk11;
      PubCommitG2 vk21;
      PubCommitG2 vk31;
      PubCommitG2 zkHash;
      PubCommitG1 zkPK;
      ComCommitG1 addr;
      ComCommitG2 branch0;
      ComCommitG2 branch1;
      ComCommitG1 fsig11;
      ComCommitG1 fsig12;
      ComCommitG1 g1branch0;
      ComCommitG1 g1branch1;
      ComCommitG1 pk;
      ComCommitG2 rinv;
      ComCommitG1 ssig11;
      ComCommitG1 ssig12;
      ComCommitG1 tsig11;
      ComCommitG1 tsig12;
      EncCommitG1 ct1branch0;
      EncCommitG1 ct2branch0;
      EncCommitG1 ekbranch0;
      EncCommitG2 fosig;
      EncCommitG1 ppB11branch0;
      EncCommitG1 ppB21branch0;
      EncCommitG1 ppBtU11branch0;
      EncCommitG1 ppBtU12branch0;
      EncCommitG1 ppBtV11branch0;
      EncCommitG1 ppBtV12branch0;
      EncCommitG2 siguser;
      EncCommitG1 zkPKbranch1;
      EncCommitG2 zkSig;

      void serialize_to(Serializer &serializer) const
      {
        serializer.serialize(addr);
        serializer.serialize(branch0);
        serializer.serialize(branch1);
        serializer.serialize(fsig11);
        serializer.serialize(fsig12);
        serializer.serialize(g1branch0);
        serializer.serialize(g1branch1);
        serializer.serialize(pk);
        serializer.serialize(rinv);
        serializer.serialize(ssig11);
        serializer.serialize(ssig12);
        serializer.serialize(tsig11);
        serializer.serialize(tsig12);
        serializer.serialize(ct1branch0);
        serializer.serialize(ct2branch0);
        serializer.serialize(ekbranch0);
        serializer.serialize(fosig);
        serializer.serialize(ppB11branch0);
        serializer.serialize(ppB21branch0);
        serializer.serialize(ppBtU11branch0);
        serializer.serialize(ppBtU12branch0);
        serializer.serialize(ppBtV11branch0);
        serializer.serialize(ppBtV12branch0);
        serializer.serialize(siguser);
        serializer.serialize(zkPKbranch1);
        serializer.serialize(zkSig);
      }
      void deserialize_from(Deserializer &deserializer)
      {
        deserializer.deserialize(addr);
        deserializer.deserialize(branch0);
        deserializer.deserialize(branch1);
        deserializer.deserialize(fsig11);
        deserializer.deserialize(fsig12);
        deserializer.deserialize(g1branch0);
        deserializer.deserialize(g1branch1);
        deserializer.deserialize(pk);
        deserializer.deserialize(rinv);
        deserializer.deserialize(ssig11);
        deserializer.deserialize(ssig12);
        deserializer.deserialize(tsig11);
        deserializer.deserialize(tsig12);
        deserializer.deserialize(ct1branch0);
        deserializer.deserialize(ct2branch0);
        deserializer.deserialize(ekbranch0);
        deserializer.deserialize(fosig);
        deserializer.deserialize(ppB11branch0);
        deserializer.deserialize(ppB21branch0);
        deserializer.deserialize(ppBtU11branch0);
        deserializer.deserialize(ppBtU12branch0);
        deserializer.deserialize(ppBtV11branch0);
        deserializer.deserialize(ppBtV12branch0);
        deserializer.deserialize(siguser);
        deserializer.deserialize(zkPKbranch1);
        deserializer.deserialize(zkSig);
      }
    };

    struct GS_Input
    {
      G1 zero1;
      G2 zero2;
      GT zerot;
      GenVarG1 g1;
      GenVarG2 g2;
      UnitVarG1 u1;
      UnitVarG2 u2;
      PubVarG1 ct1;
      PubVarG1 ct2;
      PubVarG1 ek;
      PubVarG2 h;
      PubVarG2 ppA11;
      PubVarG2 ppA21;
      PubVarG1 ppB11;
      PubVarG1 ppB21;
      PubVarG1 ppBtU11;
      PubVarG1 ppBtU12;
      PubVarG1 ppBtV11;
      PubVarG1 ppBtV12;
      PubVarG2 ppUA11;
      PubVarG2 ppUA21;
      PubVarG2 ppVA11;
      PubVarG2 ppVA21;
      PubVarG2 vk11;
      PubVarG2 vk21;
      PubVarG2 vk31;
      ComVarG1 addr;
      EncVarG2 fosig;
      ComVarG1 fsig11;
      ComVarG1 fsig12;
      ComVarG1 pk;
      ComVarG2 rinv;
      ComVarG1 ssig11;
      ComVarG1 ssig12;
      ComVarG1 tsig11;
      ComVarG1 tsig12;
      EncVarG2 siguser;

      GS_Input()
      {
        g1 = {G1::get_gen()};
        g2 = {G2::get_gen()};
        zero1 = G1::get_infty();
        zero2 = G2::get_infty();
        zerot = GT::get_unity();
      };
    };

    struct GS_Input_Public
    {
      G1 zero1;
      G2 zero2;
      GT zerot;
      GenVarG1 g1;
      GenVarG2 g2;
      PubVarG1 ct1;
      PubVarG1 ct2;
      PubVarG1 ek;
      PubVarG2 h;
      PubVarG2 ppA11;
      PubVarG2 ppA21;
      PubVarG1 ppB11;
      PubVarG1 ppB21;
      PubVarG1 ppBtU11;
      PubVarG1 ppBtU12;
      PubVarG1 ppBtV11;
      PubVarG1 ppBtV12;
      PubVarG2 ppUA11;
      PubVarG2 ppUA21;
      PubVarG2 ppVA11;
      PubVarG2 ppVA21;
      PubVarG2 vk11;
      PubVarG2 vk21;
      PubVarG2 vk31;

      GS_Input_Public()
      {
        g1 = {G1::get_gen()};
        g2 = {G2::get_gen()};
        zero1 = G1::get_infty();
        zero2 = G2::get_infty();
        zerot = GT::get_unity();
      };
    };

    struct GS_Proof
    {
      GS_Commitments commitments;
      EQ_Proof eq_e04;
      EQ_Proof eq_e01;
      EQ_Proof eq_e90;
      EQ_Proof eq_e86;
      EQ_Proof eq_e82;
      EQ_Proof eq_e89;
      EQ_Proof eq_e03;
      EQ_Proof eq_e88;
      EQ_Proof eq_e84;
      EQ_Proof eq_e02;
      EQ_Proof eq_e83;
      EQ_Proof eq_e05;
      EQ_Proof eq_e85;
      EQ_Proof eq_e81;
      EQ_Proof eq_e06;
      EQ_Proof eq_e60;
      EQ_Proof eq_e87;
      EQ_Proof eq_e70;
      EQ_Proof eq_e91;
      EQ_Proof eq_e80;

      tots::Signature ots_sig;
      tots::PublicKey ots_pk;

      void serialize_to(BilinearGroup::Serializer &serializer) const
      {
        serializer.serialize(commitments);
        serializer.serialize(eq_e04);
        serializer.serialize(eq_e01);
        serializer.serialize(eq_e90);
        serializer.serialize(eq_e86);
        serializer.serialize(eq_e82);
        serializer.serialize(eq_e89);
        serializer.serialize(eq_e03);
        serializer.serialize(eq_e88);
        serializer.serialize(eq_e84);
        serializer.serialize(eq_e02);
        serializer.serialize(eq_e83);
        serializer.serialize(eq_e05);
        serializer.serialize(eq_e85);
        serializer.serialize(eq_e81);
        serializer.serialize(eq_e06);
        serializer.serialize(eq_e60);
        serializer.serialize(eq_e87);
        serializer.serialize(eq_e70);
        serializer.serialize(eq_e91);
        serializer.serialize(eq_e80);
        serializer.serialize(ots_pk.H_1);
        serializer.serialize(ots_pk.C_1);
        serializer.serialize(ots_sig.r_0);
        serializer.serialize(ots_sig.r_1);
      }

      void deserialize_from(BilinearGroup::Deserializer &deserializer)
      {
        deserializer.deserialize(commitments);
        deserializer.deserialize(eq_e04);
        deserializer.deserialize(eq_e01);
        deserializer.deserialize(eq_e90);
        deserializer.deserialize(eq_e86);
        deserializer.deserialize(eq_e82);
        deserializer.deserialize(eq_e89);
        deserializer.deserialize(eq_e03);
        deserializer.deserialize(eq_e88);
        deserializer.deserialize(eq_e84);
        deserializer.deserialize(eq_e02);
        deserializer.deserialize(eq_e83);
        deserializer.deserialize(eq_e05);
        deserializer.deserialize(eq_e85);
        deserializer.deserialize(eq_e81);
        deserializer.deserialize(eq_e06);
        deserializer.deserialize(eq_e60);
        deserializer.deserialize(eq_e87);
        deserializer.deserialize(eq_e70);
        deserializer.deserialize(eq_e91);
        deserializer.deserialize(eq_e80);
        deserializer.deserialize(ots_pk.H_1);
        deserializer.deserialize(ots_pk.C_1);
        deserializer.deserialize(ots_sig.r_0);
        deserializer.deserialize(ots_sig.r_1);
      };

      void serialize_without_sig(BilinearGroup::Serializer &serializer) const
      {
        serializer.serialize(commitments);
        serializer.serialize(eq_e04);
        serializer.serialize(eq_e01);
        serializer.serialize(eq_e90);
        serializer.serialize(eq_e86);
        serializer.serialize(eq_e82);
        serializer.serialize(eq_e89);
        serializer.serialize(eq_e03);
        serializer.serialize(eq_e88);
        serializer.serialize(eq_e84);
        serializer.serialize(eq_e02);
        serializer.serialize(eq_e83);
        serializer.serialize(eq_e05);
        serializer.serialize(eq_e85);
        serializer.serialize(eq_e81);
        serializer.serialize(eq_e06);
        serializer.serialize(eq_e60);
        serializer.serialize(eq_e87);
        serializer.serialize(eq_e70);
        serializer.serialize(eq_e91);
        serializer.serialize(eq_e80);
        serializer.serialize(ots_pk.H_1);
        serializer.serialize(ots_pk.C_1);
      }
    };

    GS_Proof prove(CRS const &crs, GS_Input const &input);
    bool consistency_check(GS_Input const &input);
    bool verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
    bool batch_verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
  } // namespace zkp
} // namespace GS
