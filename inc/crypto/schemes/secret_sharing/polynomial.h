#pragma once
#include "crypto/schemes/secret_sharing/share.h"
#include "group.h"
#include <iostream>
#include <vector>
namespace Polynomial
{
std::vector<BilinearGroup::BN> generate_polynomial(const uint8_t &num_coefficients);
std::vector<Participants::Share> evaluate_polynomial(const std::vector<BilinearGroup::BN> polynomial, const uint8_t &n,
                                                     const BilinearGroup::BN &secret);
template <typename T>
T Horners_method(const std::vector<T> &polynomial, const BilinearGroup::BN &x, const T &neutral_element,
                 const int &num_coefficients,const int &finish)
{
  T result = neutral_element;
  for (int i = num_coefficients - 1; i >= finish; i--)
  {
    result += polynomial[i];
    result *= x;
  }
  return result;
}

BilinearGroup::BN get_lagrange_coeff(const BilinearGroup::BN &x_coord, const uint8_t &player_index, const uint8_t &n);
BilinearGroup::BN get_lagrange_coeff_start(const BilinearGroup::BN &x_coord, const uint8_t &player_index, const uint8_t start, const uint8_t &n);

} // namespace Polynomial