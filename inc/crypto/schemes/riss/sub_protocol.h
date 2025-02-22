#include "crypto/schemes/riss/riss.h"
namespace RISS
{

struct r_shares
{
  BilinearGroup::BN r_p;
  BilinearGroup::BN r_q;
};

class sub_proc
{
public:
  sub_proc(uint8_t &n, int complement_size, std::vector<BilinearGroup::BN> &y_values_p,
           std::vector<BilinearGroup::BN> &y_values_q, BilinearGroup::BN &q)
      : y_values_p(&y_values_p), y_values_q(&y_values_q), n(n), complement_size(complement_size), q(q)
  {
    shares.resize(n);
    r_values.resize(n);
  };
sub_proc(const sub_proc& other)
    : y_values_p(other.y_values_p), 
      y_values_q(other.y_values_q), 
      n(other.n), 
      complement_size(other.complement_size), 
      q(other.q), 
      r_values(other.r_values), 
      shares(other.shares), 
      my_shares_p(other.my_shares_p), 
      my_shares_q(other.my_shares_q)
{
}
  bool insert_share(int party_index, Share share)
  {
    {
      std::lock_guard<std::mutex> lock(share_mutex);
      shares[party_index].push_back(share);
    }
    return check_if_not_all_shares_received_and_calc_share(party_index);
  }; // namespace RISS
  bool insert_r_value(int party_index, BilinearGroup::BN r_value)
  {
    {
      std::lock_guard<std::mutex> lock(r_value_mutex);
      r_values[party_index] = r_value;
    }

    return check_if_not_all_shares_received_and_calc_share(party_index);
  }; // namespace RISS
  static BilinearGroup::BN calculate_share(std::vector<Share> &shares, std::vector<BilinearGroup::BN> *y_values,
                                           const BilinearGroup::BN &mod);
  r_shares finalize_sub_proc();

private:
  std::vector<BilinearGroup::BN> *y_values_p;
  std::vector<BilinearGroup::BN> *y_values_q;
  uint8_t &n;
  int complement_size;
  BilinearGroup::BN &q;
  std::mutex share_mutex;
  std::mutex r_value_mutex;
  std::mutex my_shares_mutex;
  std::vector<BilinearGroup::BN> r_values;
  std::vector<std::vector<Share>> shares;
  std::vector<BilinearGroup::BN> my_shares_p;
  std::vector<BilinearGroup::BN> my_shares_q;
  bool check_if_not_all_shares_received_and_calc_share(int &party_index);
};
} // namespace RISS