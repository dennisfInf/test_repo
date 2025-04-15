#include "networking/mpc/serialization.h"
#include "crypto/bilinear_group/group.h"
#include "Math/gfpvar.cpp"
namespace MPC
{
  bigint deserialize_bytes(const std::vector<uint8_t> &bytes)
  {
    uint16_t len = (uint16_t)bytes[0] << 8 | (uint16_t)bytes[1];
    bool negative = bytes[2] == 1;
    bigint t;
    mpz_import(t.get_mpz_t(), len, 1, sizeof(bytes[0]), 1, 0, bytes.data() + 3);

    if (negative)
    {
      std::cout << "negate number" << std::endl;
      mpz_neg(t.get_mpz_t(), t.get_mpz_t());
    }
    return t;
  };

  BilinearGroup::BN conv_decimal_string_to_bn(std::string &str)
  {
    mpz_t num;
    mpz_init_set_str(num, str.c_str(), 10);                            // Initialize num with the decimal number in str
    size_t count = (mpz_sizeinbase(num, 2) + CHAR_BIT - 1) / CHAR_BIT; // Calculate the required buffer size
    uint8_t *buffer = new uint8_t[count];                              // Allocate the buffer
    mpz_export(buffer, NULL, 1, 1, 1, 0, num);                         // Export num to buffer in big endian format
    std::vector<uint8_t> bytes(buffer, buffer + count);                // Convert the buffer to a vector
    BilinearGroup::BN res = BilinearGroup::BN::read_bytes(bytes, bytes.size());
    if (mpz_sgn(num) < 0)
    {
      BilinearGroup::BN::neg_without_mod(res, res); //  negate res
    }
    mpz_clear(num); // Clear num
    delete[] buffer;
    return res;
  }

  gfpvar_<1, 6> conv_bn_to_gfpvar(BilinearGroup::BN &val)
  {
    int capacity = val.size();
    uint8_t *buffer = new uint8_t[capacity];
    val.serialize(buffer, capacity);
    bigint t = deserialize_bytes(std::vector<uint8_t>(buffer, buffer + capacity));
    return gfpvar_<1, 6>(t);
  }

  gfp conv_bn_to_gfp(BilinearGroup::BN &val)
  {
    int capacity = val.size();
    uint8_t *buffer = new uint8_t[capacity];
    val.serialize(buffer, capacity);
    bigint t = deserialize_bytes(std::vector<uint8_t>(buffer, buffer + capacity));
    gfp p;
    to_gfp(p, t);
    return p;
  }

  BilinearGroup::BN conv_bigint_to_bn(const bigint &val)
  {
    std::string str = to_string(val);
    return conv_decimal_string_to_bn(str);
  }
  BilinearGroup::BN conv_gfp_to_bn(const gfp &val)
  {
    std::ostringstream stream;
    val.output(stream, true);
    std::string str = stream.str();
    return conv_decimal_string_to_bn(str);
  }
  void test_serialization()
  {
    BilinearGroup::BN test = BilinearGroup::BN(13372);
    gfpvar_<1, 6> test_gfpvar = MPC::conv_bn_to_gfpvar(test);
    std::cout << test_gfpvar << std::endl;
  }

  uint32_t conv_gfp_to_x_type(gfp &val)
  {
    std::ostringstream stream;

    val.output(stream, true);
    std::string str = stream.str();
    if (!str.empty() && str[0] == '-')
    {
      bigint prime = gfp::pr();
      bigint val2 = static_cast<long>(std::stoul(str));
      bigint res = prime + val2;
      return static_cast<uint32_t>(res.get_ui());
    }
    return static_cast<uint32_t>(std::stoul(str));
  }

} // namespace MPC