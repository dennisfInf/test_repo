#pragma once
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/tots/scheme.h"

namespace GS
{
  using namespace BilinearGroup;
  namespace u_reg
  {
    struct GS_Commitments
    {
      GenCommitG1 g1;
      GenCommitG2 g2;
      PubCommitG1 pk;
      EncCommitG2 sk;
      ComCommitG2 branch0;
      ComCommitG1 g1branch0;
      EncCommitG1 pkbranch0;
      ComCommitG2 branch1;
      ComCommitG1 g1branch1;
      PubCommitG2 zkHash;
      PubCommitG1 zkPK;
      EncCommitG1 zkPKbranch1;
      EncCommitG2 zkSig;

      void serialize_to(Serializer &serializer) const
      {
        serializer.serialize(branch0);
        serializer.serialize(branch1);
        serializer.serialize(g1branch0);
        serializer.serialize(g1branch1);
        serializer.serialize(sk);
        serializer.serialize(pkbranch0);
        serializer.serialize(zkPKbranch1);
        serializer.serialize(zkSig);
      }
      void deserialize_from(Deserializer &deserializer)
      {
        deserializer.deserialize(branch0);
        deserializer.deserialize(branch1);
        deserializer.deserialize(g1branch0);
        deserializer.deserialize(g1branch1);
        deserializer.deserialize(sk);
        deserializer.deserialize(pkbranch0);
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
      PubVarG1 pk;
      EncVarG2 sk;

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
      PubVarG1 pk;

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
      EQ_Proof eq_e01;
      EQ_Proof eq_e60;
      EQ_Proof eq_e70;
      EQ_Proof eq_e80;
      EQ_Proof eq_e81;
      EQ_Proof eq_e90;
      EQ_Proof eq_e91;

      tots::Signature ots_sig;
      tots::PublicKey ots_pk;

      void serialize_without_sig(BilinearGroup::Serializer &serializer) const
      {
        serializer.serialize(commitments);
        serializer.serialize(eq_e01);
        serializer.serialize(eq_e60);
        serializer.serialize(eq_e70);
        serializer.serialize(eq_e80);
        serializer.serialize(eq_e81);
        serializer.serialize(eq_e90);
        serializer.serialize(eq_e91);
        serializer.serialize(ots_pk.H_1);
        serializer.serialize(ots_pk.C_1);
      }

      void serialize_to(BilinearGroup::Serializer &serializer) const
      {
        serializer.serialize(commitments);
        serializer.serialize(eq_e01);
        serializer.serialize(eq_e60);
        serializer.serialize(eq_e70);
        serializer.serialize(eq_e80);
        serializer.serialize(eq_e81);
        serializer.serialize(eq_e90);
        serializer.serialize(eq_e91);
        serializer.serialize(ots_pk.H_1);
        serializer.serialize(ots_pk.C_1);
        serializer.serialize(ots_sig.r_0);
        serializer.serialize(ots_sig.r_1);
      }

      void deserialize_from(BilinearGroup::Deserializer &deserializer)
      {
        deserializer.deserialize(commitments);
        deserializer.deserialize(eq_e01);
        deserializer.deserialize(eq_e60);
        deserializer.deserialize(eq_e70);
        deserializer.deserialize(eq_e80);
        deserializer.deserialize(eq_e81);
        deserializer.deserialize(eq_e90);
        deserializer.deserialize(eq_e91);
        deserializer.deserialize(ots_pk.H_1);
        deserializer.deserialize(ots_pk.C_1);
        deserializer.deserialize(ots_sig.r_0);
        deserializer.deserialize(ots_sig.r_1);
      };
    };

    GS_Proof prove(CRS const &crs, GS_Input const &input);
    bool consistency_check(GS_Input const &input);
    bool verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
    bool batch_verify(CRS const &crs, GS_Proof const &proof, GS_Input_Public const &input);
  }
};
