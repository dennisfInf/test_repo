#pragma once
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "group.h"

using namespace BilinearGroup;
namespace Participants
{
  G1 simulate_mpc(std::vector<G1> shares);
  struct ciphertext
  {
    G1 c1;
    G1 c2;
  };
  class Participant
  {
  public:
    Participant();
    Participant(KeyPair key_pair);
    ciphertext encrypt(const FP &message);
    G1 compute_decryption_share(const G1 &c1, const int &n, const int &id);
    G1 compute_decryption_share_without_lagrange(const G1 &c1);

    G1 decrypt(const G1 &composed_shares, const G1 &c2);
    G1 get_public_key() { return this->key_pair.group_public; };
    G1 get_participant_public_key() { return this->key_pair.secret_pub; };

  private:
    KeyPair key_pair;
  };

  struct ciphertext_r
  {
    ciphertext c;
    BN r;
  };
  ciphertext_r encrypt(const FP &message, const G1 &public_key);

} // namespace Participants