#include "crypto/schemes/riss/sub_protocol.h"

namespace RISS
{
  r_shares sub_proc::finalize_sub_proc()
  {
    BilinearGroup::BN result = 0;
    BilinearGroup::BN result_q = 0;
    for (int i = 0; i < my_shares_p.size(); i++)
    {
      BilinearGroup::BN::add_without_mod(result, my_shares_p[i], result);
      my_shares_p[i] %= BilinearGroup::BN::get_field_prime_number();
      BilinearGroup::BN::add_without_mod(result_q, result_q, my_shares_q[i]);
    };
    result_q %= q;
    return {result, result_q};
  }

  bool sub_proc::check_if_not_all_shares_received_and_calc_share(int &party_index)
  {
    if (shares[party_index].size() == complement_size && r_values[party_index] != BilinearGroup::BN(0))
    {
      BilinearGroup::BN my_share = calculate_share(shares[party_index], y_values_p, BilinearGroup::BN::get_field_prime_number());
      BilinearGroup::BN::sub_without_mod(my_share, r_values[party_index], my_share);

      BilinearGroup::BN my_share_q = calculate_share(shares[party_index], y_values_q, q);
      BilinearGroup::BN::sub_without_mod(my_share_q, r_values[party_index], my_share_q);
      my_share_q %= q;
      {
        std::lock_guard<std::mutex> lock(my_shares_mutex);
        my_shares_p.push_back(my_share);
        my_shares_q.push_back(my_share_q);
      }
      if (my_shares_p.size() == n)
      {
        return false;
      }
      return true;
    }
    return true;
  }

  BilinearGroup::BN sub_proc::calculate_share(std::vector<Share> &shares, std::vector<BilinearGroup::BN> *y_values,
                                              const BilinearGroup::BN &mod)
  {
    BilinearGroup::BN my_share;
    for (int i = 0; i < shares.size(); i++)
    {

      if ((*y_values)[shares[i].index] == 0)
      {
        continue;
      }
      BilinearGroup::BN result;
      BilinearGroup::BN::mul_without_mod(result, shares[i].share, (*y_values)[shares[i].index]);
      result %= mod;
      BilinearGroup::BN::add_without_mod(my_share, my_share, result);
      my_share %= mod;
    }
    return my_share;
  }
} // namespace RISS