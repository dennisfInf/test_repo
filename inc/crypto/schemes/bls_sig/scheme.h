#pragma once
#include "crypto/bilinear_group/group.h"
namespace BLS
{
struct Signature{
  BilinearGroup::G2 sig;
  BilinearGroup::G2 msg;
};
class Signatures
{
public:
  Signatures(){};
  Signatures(BilinearGroup::BN secret_key, BilinearGroup::G1 public_key)
      : secret_key(secret_key), public_key(public_key){};
  void generate_keys()
  {
    this->secret_key = BilinearGroup::BN::rand();
    this->public_key = this->secret_key * BilinearGroup::G1::get_gen();
  }
  Signature sign_message(std::vector<uint8_t> m);
  static bool verify_signature(std::vector<uint8_t> m, BilinearGroup::G2 sig, BilinearGroup::G1 pk);
  BilinearGroup::G1 get_public_key() { return this->public_key; }
  BilinearGroup::BN get_secret_key(){return this->secret_key;}

private:
  BilinearGroup::BN secret_key;
  BilinearGroup::G1 public_key;
};
} // namespace BLS
