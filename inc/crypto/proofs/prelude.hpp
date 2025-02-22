#pragma once

#include <optional>
#include <tuple>
#include <variant>
#include <vector>

#include "deserializer.h"
#include "group.h"
#include "serializer.h"
#include "tmatrix.hpp"

namespace GS
{

constexpr int BATCH_SOUNDNESS_ERROR = 80;

using namespace BilinearGroup;

template <typename Group> using Vec = util::TMatrix<1, 2, Group>;

template <typename Group> using VecT = util::TMatrix<2, 1, Group>;

using G1Vec = VecT<G1>;
using G2Vec = Vec<G2>;
using BNVec = Vec<BN>;

struct PubPhantom
{
  static auto get_type() { return std::string("Pub"); }
};
struct EncPhantom
{
  static auto get_type() { return std::string("Enc"); }
};
struct ComPhantom
{
  static auto get_type() { return std::string("Com"); }
};
struct GenPhantom
{
  static auto get_type() { return std::string("Gen"); }
};
struct ScaPhantom
{
  static auto get_type() { return std::string("Sca"); }
};
struct UnitPhantom
{
  static auto get_type() { return std::string("Unit"); }
};

template <typename Group, typename Type> struct CommitmentBase
{
  Vec<Group> value;
  BN rand_r;
  BN rand_s;

  inline auto get_value() const { return value; }
  inline auto get_rand_r() const { return rand_r; }
  inline auto get_rand_s() const { return rand_s; }
  inline auto get_type() const { return Type::get_type(); }
  void serialize_to(Serializer &serializer) const { serializer.serialize(value); }
  void deserialize_from(Deserializer &deserializer) { deserializer.deserialize(value); }
};

template <typename Type> struct CommitmentBase<G1, Type>
{
  VecT<G1> value;
  BN rand_r;
  BN rand_s;

  inline auto get_value() const { return value; }
  inline auto get_rand_r() const { return rand_r; }
  inline auto get_rand_s() const { return rand_s; }
  inline auto get_type() const { return Type::get_type(); }
  void serialize_to(Serializer &serializer) const { serializer.serialize(value); }
  void deserialize_from(Deserializer &deserializer) { deserializer.deserialize(value); }
};

template <typename Group> using EncCommitmentBase = CommitmentBase<Group, EncPhantom>;

template <typename Group> using PubCommitmentBase = CommitmentBase<Group, PubPhantom>;

template <typename Group> using ComCommitmentBase = CommitmentBase<Group, ComPhantom>;

template <typename Group> using GenCommitmentBase = CommitmentBase<Group, GenPhantom>;

template <typename Group> using ScaCommitmentBase = CommitmentBase<Group, ScaPhantom>;

template <typename Group> using UnitCommitmentBase = CommitmentBase<Group, UnitPhantom>;

using EncCommitG1 = EncCommitmentBase<G1>;
using PubCommitG1 = PubCommitmentBase<G1>;
using ComCommitG1 = ComCommitmentBase<G1>;
using GenCommitG1 = GenCommitmentBase<G1>;
using ScaCommitG1 = ScaCommitmentBase<G1>;
using UnitCommitG1 = UnitCommitmentBase<G1>;

using EncCommitG2 = EncCommitmentBase<G2>;
using PubCommitG2 = PubCommitmentBase<G2>;
using ComCommitG2 = ComCommitmentBase<G2>;
using GenCommitG2 = GenCommitmentBase<G2>;
using ScaCommitG2 = ScaCommitmentBase<G2>;
using UnitCommitG2 = UnitCommitmentBase<G2>;

template <typename Group>
using var_com_g_t = std::variant<EncCommitmentBase<Group>, PubCommitmentBase<Group>, ComCommitmentBase<Group>,
                                 GenCommitmentBase<Group>, ScaCommitmentBase<Group>, UnitCommitmentBase<Group>>;

using var_com_t = std::variant<EncCommitG1, PubCommitG1, ComCommitG1, GenCommitG1, ScaCommitG1, UnitCommitG1,
                               EncCommitG2, PubCommitG2, ComCommitG2, GenCommitG2, ScaCommitG2, UnitCommitG2>;

using var_com_g1_t = var_com_g_t<G1>;
using var_com_g2_t = var_com_g_t<G2>;

template <typename Group, typename Type, typename ComTo = void> struct VariableBase
{
  Group value;

  operator Group() const { return value; }

  auto get_value() const { return value; }
  auto get_type() const { return Type::get_type(); }
};

template <> struct VariableBase<BN, UnitPhantom>
{

  operator BN() const { return BN(1); }

  auto get_value() const { return BN(1); }
  auto get_type() const { return UnitPhantom::get_type(); }
};

template <typename Group> using EncVariableBase = VariableBase<Group, EncPhantom>;

template <typename Group> using PubVariableBase = VariableBase<Group, PubPhantom>;

template <typename Group> using ComVariableBase = VariableBase<Group, ComPhantom>;

template <typename Group> using GenVariableBase = VariableBase<Group, GenPhantom>;

template <typename ComTo> using ScaVariableBase = VariableBase<BN, ScaPhantom, ComTo>;

template <typename ComTo> using UnitVariableBase = VariableBase<BN, UnitPhantom, ComTo>;

using EncVarG1 = EncVariableBase<G1>;
using PubVarG1 = PubVariableBase<G1>;
using ComVarG1 = ComVariableBase<G1>;
using GenVarG1 = GenVariableBase<G1>;
using ScaVarG1 = ScaVariableBase<G1>;
using UnitVarG1 = UnitVariableBase<G1>;

using EncVarG2 = EncVariableBase<G2>;
using PubVarG2 = PubVariableBase<G2>;
using ComVarG2 = ComVariableBase<G2>;
using GenVarG2 = GenVariableBase<G2>;
using ScaVarG2 = ScaVariableBase<G2>;
using UnitVarG2 = UnitVariableBase<G2>;

using var_var_t = std::variant<EncVarG1, PubVarG1, ComVarG1, GenVarG1, ScaVarG1, UnitVarG1, EncVarG2, PubVarG2,
                               ComVarG2, GenVarG2, ScaVarG2, UnitVarG2>;

template <typename Group>
using var_var_g_t = std::variant<EncVariableBase<Group>, PubVariableBase<Group>, ComVariableBase<Group>,
                                 GenVariableBase<Group>, ScaVariableBase<Group>, UnitVariableBase<Group>>;

using var_var_g1_t = var_var_g_t<G1>;
using var_var_g2_t = var_var_g_t<G2>;

namespace util
{

template <typename GroupVec, typename GroupCom, typename ComType>
auto operator*(Vec<GroupVec> const &vec, CommitmentBase<GroupCom, ComType> const &com)
{
  return vec * com.get_value();
}

template <typename ElementType, size_t Rows, size_t Cols, typename Other_T>
auto operator*(util::TMatrix<Rows, Cols, ElementType> const &m, Other_T const &factor) -> auto
{

  using result_element_type = decltype(m(0, 0) * factor);

  util::TMatrix<Rows, Cols, result_element_type> result;
  for (size_t r = 0; r < Rows; r++)
  {
    for (size_t c = 0; c < Cols; c++)
    {
      result(r, c) = m(r, c) * factor;
    }
  }
  return result;
}

template <typename ElementType, size_t Rows, size_t Cols, typename Other_T>
auto operator*(Other_T const &factor, util::TMatrix<Rows, Cols, ElementType> const &m) -> auto
{

  using result_element_type = decltype(m(0, 0) * factor);

  util::TMatrix<Rows, Cols, result_element_type> result;
  for (size_t r = 0; r < Rows; r++)
  {
    for (size_t c = 0; c < Cols; c++)
    {
      result(r, c) = m(r, c) * factor;
    }
  }
  return result;
}

template <typename GroupLeft, typename GroupRight, typename ComRight>
auto operator*(VecT<GroupLeft> const &vec, CommitmentBase<GroupRight, ComRight> const &c)
{
  return vec * c.value;
}

} // namespace util

struct CRS
{

  void v(G1Vec &arg) const { arg = this->v1; };
  void v(G2Vec &arg) const { arg = this->v2; };

  void w(G1Vec &arg) const { arg = this->w1; };
  void w(G2Vec &arg) const { arg = this->w2; };

  void u(G1Vec &arg) const { arg = this->u1; };
  void u(G2Vec &arg) const { arg = this->u2; };

  G1Vec v1;
  G1Vec w1;
  G1Vec u1;
  G2Vec v2;
  G2Vec w2;
  G2Vec u2;
  G1 H;
  G1 bls_pk;
  BN xi;
  BN psi;
  void serialize_to(BilinearGroup::Serializer &serializer) const
  {
    serializer.serialize(v1);
    serializer.serialize(w1);
    serializer.serialize(u1);
    serializer.serialize(v2);
    serializer.serialize(w2);
    serializer.serialize(u2);
    serializer.serialize(H);
    serializer.serialize(bls_pk);
    serializer.serialize(xi);
    serializer.serialize(psi);
  }
  void deserialize_from(Deserializer &deserializer)
  {
    deserializer.deserialize(v1);
    deserializer.deserialize(w1);
    deserializer.deserialize(u1);
    deserializer.deserialize(v2);
    deserializer.deserialize(w2);
    deserializer.deserialize(u2);
    deserializer.deserialize(H);
    deserializer.deserialize(bls_pk);
    deserializer.deserialize(xi);
    deserializer.deserialize(psi);
  }
  void precompute(){
    H.precompute();
    bls_pk.precompute();
  }
};

bool operator==(GS::CRS const &lhs, GS::CRS const &rhs);

struct EQ_Proof
{
  GS::G2Vec pi_v_1;
  GS::G1Vec pi_v_2;
  GS::G2Vec pi_w_1;
  GS::G1Vec pi_w_2;

  void serialize_to(BilinearGroup::Serializer &serializer) const
  {
    serializer.serialize(pi_v_1);
    serializer.serialize(pi_v_2);
    serializer.serialize(pi_w_1);
    serializer.serialize(pi_w_2);
  }

  void deserialize_from(BilinearGroup::Deserializer &deserializer)
  {
    deserializer.deserialize(pi_v_1);
    deserializer.deserialize(pi_v_2);
    deserializer.deserialize(pi_w_1);
    deserializer.deserialize(pi_w_2);
  }
};

struct SerializationData
{
  std::vector<uint8_t> buffer_xi, buffer_v1, buffer_w1[2], buffer_u1[2];
  uint8_t sign_xi;
  G1 v1_1_copy;
  G1Vec u1_copy, w1_copy;
  BN xi_copy;

  std::vector<uint8_t> buffer_psi, buffer_v2, buffer_w2[2], buffer_u2[2];
  uint8_t sign_psi;
  G2 v2_1_copy;
  G2Vec u2_copy, w2_copy;
  BN psi_copy;
};

} // namespace GS

namespace GS
{

std::unique_ptr<CRS> setup_crs();
CRS setup_crs_and_serialize(int fd);
CRS setup_crs_by_deserialization(int fd);
CRS setup_crs_test_serialize(SerializationData &sd, int fd);

template <typename Group, typename ComType> auto operator-(CommitmentBase<Group, ComType> const &c, Vec<Group> const &v)
{
  return c.get_value() - v;
}

template <typename Group, typename ComType>
auto operator-(CommitmentBase<Group, ComType> const &c, VecT<Group> const &v)
{
  return c.get_value() - v;
}

template <typename GroupFactor, typename ComType, typename GroupCom>
auto operator*(CommitmentBase<GroupCom, ComType> const &c, GroupFactor const &factor)
{
  return c.get_value() * factor;
}
} // namespace GS

#include "out_funcs.hpp"
