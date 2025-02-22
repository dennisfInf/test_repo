#include "crypto/schemes/secret_sharing/polynomial.h"
#include "crypto/schemes/secret_sharing/share.h"
#include <iostream>
namespace Polynomial
{
// generates a random polynomial of degree num_coefficients - 1 by sampling random coefficients
std::vector<BilinearGroup::BN> generate_polynomial(const uint8_t &num_coefficients)
{
  std::vector<BilinearGroup::BN> polynomial;
  polynomial.resize(num_coefficients);
  std::vector<std::future<void>> futures;
  for (int i = 0; i < num_coefficients; i++)
  {
    futures.push_back(
        BilinearGroup::pool.push([&coefficient = polynomial[i]](int) { coefficient = BilinearGroup::BN::rand(); }));
  }
  for (auto &f : futures)
  {
    f.wait();
  }
  return polynomial;
};
// evaluates the polynomial using horners method and adds the secret as a constant to the result

std::vector<Participants::Share> evaluate_polynomial(const std::vector<BilinearGroup::BN> polynomial, const uint8_t &n,
                                                     const BilinearGroup::BN &secret)
{
  std::vector<Participants::Share> shares;
  shares.resize(n);
  std::vector<std::future<void>> futures;
  for (int i = 1; i <= n; i++)
  {
    futures.push_back(BilinearGroup::pool.push(
        [&share = shares[i - 1], i, &polynomial, &secret](int)
        {
          BilinearGroup::BN value = Horners_method<BilinearGroup::BN>(polynomial, BilinearGroup::BN(i),
                                                                      BilinearGroup::BN(0), polynomial.size(), 0);
          value += secret;
          share = Participants::Share(value, i);
        }));
  };
  for (auto &f : futures)
  {
    f.wait();
  }
  return shares;
};

BilinearGroup::BN get_lagrange_coeff(const BilinearGroup::BN &x_coord, const uint8_t &player_index, const uint8_t &n)
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
    numerator = numerator * (j_bn - x_coord);
    denominator = denominator * (j_bn - player_index_bn);
  }
  if (denominator == BilinearGroup::BN(0))
  {
    std::cout << "denominator is zero (duplicate shares provided)" << std::endl;
    exit(1);
  }
  BilinearGroup::BN::mod_inverse(denominator, denominator, BilinearGroup::G1::get_group_order());
  numerator = numerator * denominator;
  return numerator;
}

} // namespace Polynomial