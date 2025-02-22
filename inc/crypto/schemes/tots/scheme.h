#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
namespace tots
{
struct PublicKey
{
  BilinearGroup::G1 H_1;
  BilinearGroup::G1 C_1;
};
struct KeyMaterial
{
  BilinearGroup::BN w;
  BilinearGroup::BN s;
  PublicKey pk;
};

struct Signature
{
  BilinearGroup::BN r_0;
  BilinearGroup::BN r_1;
};
class OTS
{
public:
  OTS()
  {
    setup();
    keygen();
  };
  OTS(BilinearGroup::G1 H)
  {
    this->H = H;
    keygen();
  };
  static bool verify(std::vector<uint8_t> message, Signature sig, PublicKey pk, BilinearGroup::G1 H);
  Signature sign(std::vector<uint8_t> message);
  PublicKey get_public_key(){return this->key_mat.pk;};
  static BilinearGroup::G2 hash_public_key(PublicKey pk){return BilinearGroup::hash_G1_elements<BilinearGroup::G2>({pk.H_1, pk.C_1});};


private:
  BilinearGroup::G1 H;
  KeyMaterial key_mat;
  void setup() { this->H = BilinearGroup::G1::rand(); };
  void keygen()
  {
    BilinearGroup::BN w = BilinearGroup::BN::rand();
    BilinearGroup::BN s = BilinearGroup::BN::rand();

    this->key_mat = {w, s, {w * BilinearGroup::G1::get_gen(), s * BilinearGroup::G1::get_gen()}};
  };
};
}; // namespace tots