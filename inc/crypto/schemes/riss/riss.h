#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include <list>
#include <vector>

namespace RISS
{
struct Share
{
  BilinearGroup::BN share;
  int index;
};
struct RISSShares
{
  BilinearGroup::BN r;
  std::vector<Share> shares;
};

struct RISSInteger
{
  RISSShares riss_shares;
  BilinearGroup::BN secret;
};
class Scheme
{
public:
  Scheme(uint8_t my_index, uint8_t t, uint8_t n, uint8_t l, uint8_t k, BilinearGroup::BN q)
      : my_index(my_index), t(t), n(n), l(l), k(k), q(q)
  {
    la_grange_coeffs_p = calculate_lagrange_coeffs();
  };
  RISSInteger get_secret_ras_r_value();
  BilinearGroup::BN get_initial_share(std::vector<Share> &shares, BilinearGroup::BN &r_value);

  std::vector<BilinearGroup::BN> &get_y_values_p() { return y_values_p; }
  std::vector<BilinearGroup::BN> &get_y_values_q() { return y_values_q; }
  int calc_sets_and_complements();
  void setup()
  {
    y_values_p = calc_y_values(BilinearGroup::BN::get_group_order());
    y_values_q = calc_y_values(q);
  }
  std::vector<std::pair<std::vector<int>, std::vector<int>>> get_sets_and_complements();
  BilinearGroup::BN calc_share_plus_r(BilinearGroup::BN &f_p_share, BilinearGroup::BN &riss_share);
  BilinearGroup::BN open_value(std::vector<Share> &shares);
  BilinearGroup::BN convert_opened_value(BilinearGroup::BN &r_plus_b, BilinearGroup::BN &r_q);

private:
  std::vector<BilinearGroup::BN> calc_y_values(const BilinearGroup::BN mod);
  std::vector<BilinearGroup::BN> calculate_lagrange_coeffs();
  std::vector<std::pair<std::vector<int>, std::vector<int>>> sets_and_complement;
  std::vector<BilinearGroup::BN> y_values_p;
  std::vector<BilinearGroup::BN> y_values_q;
  uint8_t my_index;
  uint8_t t;
  uint8_t n;
  uint8_t l;
  uint8_t k;
  BilinearGroup::BN q;
  std::vector<BilinearGroup::BN> la_grange_coeffs_p;
};
BilinearGroup::BN get_lagrange_coeff_mod(const BilinearGroup::BN &x_coord, const uint8_t &player_index,
                                         const uint8_t &n, BilinearGroup::BN &mod);
std::vector<BilinearGroup::BN> test_riss(int n, int t);
void test_sub_protocol(uint8_t n, uint8_t t);

} // namespace RISS