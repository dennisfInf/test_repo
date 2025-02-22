#pragma once

namespace GS
{
using namespace util;

template <typename CRS_Type> constexpr bool is_pcc(CRS_Type const &crs)
{
  (void)crs;
  if constexpr (std::is_same_v<CRS_Type, CRS>)
  {
    return false;
  }
  else
  {
    return true;
  }
}

template <typename Group, typename ComType> inline Group batch_c(CommitmentBase<Group, ComType> const &c, BN const &exp)
{
  if constexpr (std::is_same_v<Group, G1>)
  {
    return (util::TMatrix<1, 2, BN>{exp, BN(1)} * c.get_value())(0, 0);
  }
  else
  {
    return (c.get_value() * util::TMatrix<2, 1, BN>{exp, BN(1)})(0, 0);
  }
}

template <typename ComTo, typename CRS_Type>
UnitCommitmentBase<ComTo> commit(CRS_Type const &crs, UnitVariableBase<ComTo> const &var)
{
  (void)var;
  if constexpr (std::is_same_v<ComTo, G1>)
  {
    VecT<ComTo> u;
    crs.u(u);
    auto comm = u;
    return UnitCommitmentBase<ComTo>{comm, BN(0), BN(0)};
  }
  else
  {
    Vec<ComTo> u;
    crs.u(u);
    auto comm = u;
    return UnitCommitmentBase<ComTo>{comm, BN(0), BN(0)};
  }
}

template <typename ComTo, typename CRS_Type>
ScaCommitmentBase<ComTo> commit(CRS_Type const &crs, ScaVariableBase<ComTo> const &var)
{
  auto r = BN::rand();
  if constexpr (std::is_same_v<ComTo, G1>)
  {
    VecT<BN> e = {0, 1};
    VecT<ComTo> v;
    VecT<ComTo> u;
    crs.v(v);
    crs.u(u);
    auto comm = u * var.get_value() + v * r;
    return ScaCommitmentBase<ComTo>{comm, r, BN(0)};
  }
  else
  {
    Vec<ComTo> v;
    Vec<ComTo> u;
    crs.v(v);
    crs.u(u);
    auto comm = u * var.get_value() + v * r;
    return ScaCommitmentBase<ComTo>{comm, r, BN(0)};
  }
}

template <typename Group, typename CRS_Type>
EncCommitmentBase<Group> commit(CRS_Type const &crs, EncVariableBase<Group> const &var)
{
  auto r = BN::rand();
  if constexpr (std::is_same_v<Group, G1>)
  {
    VecT<BN> e = {0, 1};
    VecT<Group> v;
    crs.v(v);
    auto comm = e * var.value + v * r;
    return EncCommitmentBase<Group>{comm, r, BN(0)};
  }
  else
  {
    BNVec e = {0, 1};
    Vec<Group> v;
    crs.v(v);
    auto comm = var.value * e + v * r;
    return EncCommitmentBase<Group>{comm, r, BN(0)};
  }
}

template <typename Group, typename CRS_Type> EncCommitmentBase<Group> commit(CRS_Type const &crs, Group const &var)
{
  auto r = BN::rand();
  if constexpr (std::is_same_v<Group, G1>)
  {
    VecT<BN> e = {0, 1};
    VecT<Group> v;
    crs.v(v);
    auto comm = e * var + v * r;
    return EncCommitmentBase<Group>{comm, r, BN(0)};
  }
  else
  {
    BNVec e = {0, 1};
    Vec<Group> v;
    crs.v(v);
    auto comm = var * e + v * r;
    return EncCommitmentBase<Group>{comm, r, BN(0)};
  }
}

template <typename Group, typename CRS_Type>
ComCommitmentBase<Group> commit(CRS_Type const &crs, ComVariableBase<Group> const &var)
{
  auto r = BN::rand();
  auto s = BN::rand();

  if constexpr (std::is_same_v<Group, G1>)
  {

    VecT<BN> e = {0, 1};
    VecT<Group> v;
    crs.v(v);

    if constexpr (false)
    {

      auto comm = e * var.value + v * ((r + crs.ro * s) % G1::get_group_order());
      return ComCommitmentBase<Group>{comm, r, s};
    }
    else
    {

      VecT<Group> w;
      crs.w(w);
      auto comm = e * var.value + v * r + w * s;
      return ComCommitmentBase<Group>{comm, r, s};
    }
  }
  else
  {

    Vec<BN> e = {0, 1};
    Vec<Group> v;
    crs.v(v);

    if constexpr (false)
    {

      auto comm = var.value * e + v * ((r + crs.sig * s) % G2::get_group_order());
      return ComCommitmentBase<Group>{comm, r, s};
    }
    else
    {

      Vec<Group> w;
      crs.w(w);

      auto comm = var.value * e + v * r + w * s;
      return ComCommitmentBase<Group>{comm, r, s};
    }
  }
}

template <typename Group, typename CRS_Type>
GenCommitmentBase<Group> commit(CRS_Type const &crs, GenVariableBase<Group> const &var)
{
  (void)crs;
  if constexpr (std::is_same_v<Group, G1>)
  {
    VecT<BN> e = {0, 1};

    auto comm = e * var.value;
    return GenCommitmentBase<Group>{comm, BN(0), BN(0)};
  }
  else
  {
    Vec<BN> e = {0, 1};

    auto comm = var.value * e;
    return GenCommitmentBase<Group>{comm, BN(0), BN(0)};
  }
}

template <typename Group, typename CRS_Type>
PubCommitmentBase<Group> commit(CRS_Type const &crs, PubVariableBase<Group> const &var)
{
  (void)crs;
  if constexpr (std::is_same_v<G1, Group>)
  {
    VecT<BN> e = {0, 1};
    auto comm = e * var.value;
    return PubCommitmentBase<Group>{comm, BN(0), BN(0)};
  }
  else
  {
    BNVec e = {0, 1};
    auto comm = var.value * e;
    return PubCommitmentBase<Group>{comm, BN(0), BN(0)};
  }
}

template <typename Group, typename CRS_Type>
var_com_g_t<Group> commit(CRS_Type const &crs, var_var_g_t<Group> const &var)
{
  auto lambda = [&](auto &&v) {
    var_com_g_t<Group> result = commit(crs, v);
    return result;
  };
  return visit(lambda, var);
}

template <typename Group>
std::vector<var_com_g_t<Group>> commit_vec(CRS const &crs, std::vector<var_var_g_t<Group>> const &variables)
{
  std::vector<var_com_g_t<Group>> result;
  for (auto const &variable_variant : variables)
  {
    result.push_back(commit(crs, variable_variant));
  }
  return result;
}
} // namespace GS
