#include "crypto/schemes/riss/riss.h"
#include "crypto/schemes/riss/sub_protocol.h"

namespace RISS
{

RISSInteger Scheme::get_secret_ras_r_value()
{
  std::vector<std::future<void>> futures;
  BilinearGroup::BN secret;
  std::vector<Share> shares;
  shares.resize(sets_and_complement.size());
  futures.push_back(BilinearGroup::pool.push([this, &secret](int) { secret = BilinearGroup::BN::rand(this->l, 1); }));
  BilinearGroup::BN sum_shares = BilinearGroup::BN::get_infty();
  std::mutex m;
  for (int i = 0; i < sets_and_complement.size(); i++)
  {
    futures.push_back(BilinearGroup::pool.push(
        [this, &sum_shares, &m, &complement = sets_and_complement[i].second, i, &share = shares[i]](int)
        {
          BilinearGroup::BN R_A = BilinearGroup::BN::rand(this->l + k, 1);
          share = Share{R_A, i};
          std::lock_guard<std::mutex> lock(m);
          sum_shares = sum_shares + R_A;
        }));
  };
  for (auto &f : futures)
  {
    f.wait();
  }
  return {{(secret + sum_shares), shares}, secret};
}

int Scheme::calc_sets_and_complements()
{
  std::vector<int> v(n);
  std::fill(v.begin(), v.begin() + t, 1);

  // Vector to store all combinations
  int my_index_in_comp = 0;
  do
  {
    std::vector<int> combination, complement;
    for (int i = 0; i < n; ++i)
    {
      if (v[i])
      {
        combination.push_back(i); // Elements range from 0 to n-1
      }
      else
      {
        complement.push_back(i);
        if (i == my_index - 1)
        {
          my_index_in_comp++;
        }
      }
    }
    sets_and_complement.push_back({combination, complement});
  } while (std::prev_permutation(v.begin(), v.end()));
  return my_index_in_comp;
}

std::vector<BilinearGroup::BN> Scheme::calc_y_values(const BilinearGroup::BN mod)
{
  std::vector<BilinearGroup::BN> y_values;
  for (auto &set_and_complement : this->sets_and_complement)
  {
    std::vector<int> a = set_and_complement.first;
    // Let Roots be the roots of the polynomial (r1, r2, ..., rt)
    // Let c be the point at which the polynomial equals 1
    // Let d be the point at which you want to evaluate the polynomial
    BilinearGroup::BN c = BilinearGroup::BN(0);
    BilinearGroup::BN result = BilinearGroup::BN(1);
    int _index = my_index;
    BilinearGroup::BN index = BilinearGroup::BN(_index);
    for (auto root : a)
    {
      // add 1, because elements in a are 0-indexed
      BilinearGroup::BN _root = root;
      BilinearGroup::BN::add_without_mod(_root, _root, 1);
      BilinearGroup::BN numerator;
      BilinearGroup::BN::sub_without_mod(numerator, index, _root);
      BilinearGroup::BN denominator;
      BilinearGroup::BN::sub_without_mod(denominator, c, _root);
      BilinearGroup::BN::mod_inverse(denominator, denominator, mod);
      BilinearGroup::BN::mul_without_mod(result, result, numerator);
      result %= mod;
      BilinearGroup::BN::mul_without_mod(result, result, denominator);
      result %= mod;
    };
    y_values.push_back(result);
  }
  return y_values;
}
std::vector<std::pair<std::vector<int>, std::vector<int>>> Scheme::get_sets_and_complements()
{
  return sets_and_complement;
}

BilinearGroup::BN Scheme::get_initial_share(std::vector<Share> &shares, BilinearGroup::BN &r_value)
{
  return r_value - sub_proc::calculate_share(shares, &get_y_values_p(), BilinearGroup::BN::get_group_order());
}

BilinearGroup::BN get_lagrange_coeff_mod(const BilinearGroup::BN &x_coord, const uint8_t &player_index,
                                         const uint8_t &n, BilinearGroup::BN &mod)
{

  BilinearGroup::BN player_index_bn = BilinearGroup::BN(player_index);
  BilinearGroup::BN numerator = BilinearGroup::BN(1);
  BilinearGroup::BN denominator = BilinearGroup::BN(1);
  // To Do: Maybe do chunking for parallelization
  for (int j = 1; j < n + 1; j++)
  {
    if (j == player_index)
    {
      continue;
    }
    BilinearGroup::BN j_bn = BilinearGroup::BN(j);
    BilinearGroup::BN sub_res;
    BilinearGroup::BN::sub_without_mod(sub_res, j_bn, x_coord);
    BilinearGroup::BN::mul_without_mod(numerator, numerator, sub_res);

    BilinearGroup::BN::sub_without_mod(sub_res, j_bn, player_index_bn);
    BilinearGroup::BN::mul_without_mod(denominator, denominator, sub_res);
    denominator %= mod;
  }
  if (denominator == BilinearGroup::BN(0))
  {
    std::cout << "denominator is zero (duplicate shares provided)" << std::endl;
    exit(1);
  }
  BilinearGroup::BN::mod_inverse(denominator, denominator, mod);
  BilinearGroup::BN::mul_without_mod(numerator, numerator, denominator);
  numerator %= mod;
  return numerator;
}

BilinearGroup::BN Scheme::calc_share_plus_r(BilinearGroup::BN &f_p_share, BilinearGroup::BN &riss_share)
{
  return f_p_share + (riss_share * la_grange_coeffs_p[my_index - 1]);
}

std::vector<BilinearGroup::BN> Scheme::calculate_lagrange_coeffs()
{
  BilinearGroup::BN mod = BilinearGroup::BN::get_group_order();
  std::vector<BilinearGroup::BN> la_grange_coeffs;
  la_grange_coeffs.resize(n);
  std::vector<std::future<void>> futures;
  for (int i = 1; i < n + 1; i++)
  {
    futures.push_back(BilinearGroup::pool.push([this, &mod, i, &la_grange_coeff = la_grange_coeffs[i - 1]](int)
                                               { la_grange_coeff = get_lagrange_coeff_mod(0, i, t+1, mod); }));
  }
  for (auto &f : futures)
  {
    f.wait();
  }
  return la_grange_coeffs;
}

BilinearGroup::BN Scheme::open_value(std::vector<Share> &shares)
{
  BilinearGroup::BN result = BilinearGroup::BN(0);
  for (auto &share : shares)
  {
    result += share.share;
  }
  return result;
}

BilinearGroup::BN Scheme::convert_opened_value(BilinearGroup::BN &r_plus_b, BilinearGroup::BN &r_q)
{
  BilinearGroup::BN converted_share = r_plus_b % q;
  BilinearGroup::BN::sub_without_mod(converted_share, converted_share, r_q);
  converted_share %= q;
  // MP-SPDZ takes additive shares as input
  BilinearGroup::BN::mul_without_mod(converted_share, converted_share, get_lagrange_coeff_mod(0, my_index, t+1, q));
  return (converted_share % q);
}

std::vector<BilinearGroup::BN> test_riss(int n, int t)
{
  std::vector<Scheme> players;
  std::vector<RISSInteger> riss_ints;
  std::vector<std::vector<BilinearGroup::BN>> initial_shares;
  initial_shares.resize(n);
  for(int i=0;i<n;i++){
    players.push_back(Scheme(i+1, t, n, 4, 8, BilinearGroup::BN::get_group_order()));
    riss_ints.push_back(players[i].get_secret_ras_r_value());
  }

 for(int j=0;j<n;j++){
  for(int i=0;i<n;i++){
    initial_shares[j].push_back(players[j].get_initial_share(riss_ints[i].riss_shares.shares, riss_ints[i].riss_shares.r));
  }
 }

BilinearGroup::BN mod = BilinearGroup::BN::get_group_order();

 std::vector<BilinearGroup::BN> la_grange_coeffs;
     BilinearGroup::BN left;
    BilinearGroup::BN right;
    std::vector<BilinearGroup::BN> final_shares;
    for(int i=1;i<=t+1;i++){
      la_grange_coeffs.push_back(get_lagrange_coeff_mod(0, i, t+1, mod));
      BilinearGroup::BN player_shares_sum;
      for(int j=0;j<n;j++){
        player_shares_sum += initial_shares[i-1][j];
      }
      final_shares.push_back(player_shares_sum);
      left += (player_shares_sum * la_grange_coeffs[i-1]);
      right+= riss_ints[i-1].secret;
    }
  if (left == right)
  {
    std::cout << "Riss test passed" << std::endl;
  }
  else
  {
    std::cout << "Riss test failed" << std::endl;
  }
  final_shares.push_back(right);
  return final_shares;
}

void test_sub_protocol(uint8_t n, uint8_t t)
{
  std::string str1 = "249 213 225 206 39 184 58 153";
  std::stringstream ss(str1);
  std::vector<uint8_t> vec1;
  int num;
  while (ss >> num)
  {
    vec1.push_back(static_cast<uint8_t>(num));
  }

  BilinearGroup::BN q = BilinearGroup::BN::read_bytes(vec1, 8);
  std::vector<Scheme> players;
  for(int i=1;i<=n;i++){
    players.push_back(Scheme(i, t, n, 6, 2, q));
    int occur = players[i-1].calc_sets_and_complements();
    std::cout << "player" << i << " occurences: " << occur << std::endl;
    players[i-1].setup();
  }
  std::vector<std::pair<std::vector<int>, std::vector<int>>> sets_and_complements = players[0].get_sets_and_complements();
  int comp_size = sets_and_complements[0].second.size();
  std::vector<RISSInteger> riss_ints;
  for (int i = 0; i < n; i++)
  {
    riss_ints.push_back(players[i].get_secret_ras_r_value());
  }
  {
    std::vector<sub_proc> sub_procs;
    for (int i = 0; i < n; i++)
    {
      sub_procs.push_back(sub_proc(n, comp_size, players[i].get_y_values_p(), players[i].get_y_values_q(), q));
      for(int j=0;j<n;j++){
        sub_procs[i].insert_r_value(j, riss_ints[j].riss_shares.r);
      }
    }
    int counter = 0;
    for (auto &set_and_complement : sets_and_complements)
    {
      for (auto &i : set_and_complement.second)
      {
        for(int j=0;j<n;j++){
          sub_procs[i].insert_share(j, riss_ints[j].riss_shares.shares[counter]);
        }
      }
      counter++;
    }
    std::vector<r_shares> r_shares;
    for(auto &proc:sub_procs){
      r_shares.push_back(proc.finalize_sub_proc());
    }
    std::vector<BilinearGroup::BN> la_grange_coeffs_p;
    BilinearGroup::BN mod_p = BilinearGroup::BN::get_group_order();
    BilinearGroup::BN left;
    BilinearGroup::BN right;
    for(int i=1;i<=t+1;i++){
      la_grange_coeffs_p.push_back(get_lagrange_coeff_mod(0, i, t+1, mod_p));
      left += (r_shares[i-1].r_p * la_grange_coeffs_p[i-1]);
      right+= riss_ints[i-1].secret;
    }
    if (left == right)
    {
      std::cout << "Riss test sub mod p passed" << std::endl;
    }
    else
    {
      std::cout << "Riss test sub mod p failed" << std::endl;
    }
        std::vector<BilinearGroup::BN> la_grange_coeffs_q;
        BilinearGroup::BN result_q;
    for(int i=1;i<=t+1;i++){
      la_grange_coeffs_q.push_back(get_lagrange_coeff_mod(0, i, t+1, q));
      BilinearGroup::BN mul_res;
      BilinearGroup::BN::mul_without_mod(mul_res, r_shares[i-1].r_q , la_grange_coeffs_q[i-1]);
      mul_res %= q;
          BilinearGroup::BN::add_without_mod(result_q, result_q, mul_res);
          result_q %=q;
    }
    if (result_q == right)
    {
      std::cout << "Riss test sub mod q passed" << std::endl;
    }
    else
    {
      std::cout << "Riss test sub mod q failed" << std::endl;
    }

    std::vector<BilinearGroup::BN> secrets = test_riss(n,t);
      std::vector<RISS::Share> shamir_shares;
    for(int i=0;i<n;i++){
      BilinearGroup::BN val = secrets[i] * la_grange_coeffs_p[i];
      BilinearGroup::BN shamir_share = players[i].calc_share_plus_r(val, r_shares[i].r_p);
      shamir_shares.push_back({shamir_share, i});
    }
    BilinearGroup::BN fp_val_plus_r = players[0].open_value(shamir_shares);
    if (fp_val_plus_r == secrets[n] + right)
    {
      std::cout << "b+r opened correctly" << std::endl;
    }
    else
    {
      std::cout << "b+r did not open correctly" << std::endl;
    }
    BilinearGroup::BN result_b_q;
    for(int i=0;i<n;i++){
      result_b_q+= players[i].convert_opened_value(fp_val_plus_r, r_shares[i].r_q);
    }
    result_b_q %= q;
    if (result_b_q == secrets[n])
    {
      std::cout << "b mod q opened correctly" << std::endl;
    }
    else
    {
      std::cout << "b mod q did not open correctly" << std::endl;
    }
  }
}

} // namespace RISS
