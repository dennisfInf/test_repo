#include "crypto/schemes/threshold_el_gamal/helpers.h"
#include "crypto/schemes/threshold_el_gamal/participant.h"
#include <cassert>
#include <iostream>
using namespace Participants;

// Converts a vector of uint8_t to a string for debugging purposes
std::string Participants::convert_array_to_string(uint8_t *buffer, size_t capacity)
{
  std::ostringstream convert;
  for (int a = 0; a < capacity; a++)
  {
    convert << (int)buffer[a];
  }
  return convert.str();
}
std::string Participants::convert_vec_uint8_to_string(std::vector<uint8_t> vec)
{
  std::ostringstream convert;
  for (int a = 0; a < vec.size(); a++)
  {
    convert << (int)vec[a];
  }
  return convert.str();
}

// Does bitwise xor for two byte arrays and returns the result, checks if their size matches beforehand
std::vector<uint8_t> Participants::xor_arrays(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
  assert(a.size() == b.size());
  std::vector<uint8_t> result(a.size());
  for (size_t i = 0; i < a.size(); i++)
  {
    result[i] = a[i] ^ b[i];
  }
  return result;
}