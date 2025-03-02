#include "crypto/schemes/threshold_el_gamal/participant.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "crypto/schemes/threshold_el_gamal/helpers.h"
#include <iostream>

Participants::Participant::Participant() {}

// Initializes a Participant with a secret share and an id
Participants::Participant::Participant(KeyPair key_pair) { this->key_pair = key_pair; }

// encrypts a 256 bit message with El Gamal on G1 in BLS12-381. Returns (c1,c2)
Participants::ciphertext Participants::Participant::encrypt(const FP &message)
{
  return Participants::encrypt(message, this->key_pair.group_public).c;
}

Participants::ciphertext_r Participants::encrypt(const FP &message, const G1 &public_key)
{
  BilinearGroup::G1 msg = BilinearGroup::G1::koblitz_encode_message(message);
  BN r = BN::rand();
  G1 gr;
  std::future<void> f = pool.push([&r, &gr](int)
                                  { gr = G1::get_gen() * r; });
  G1 yr = public_key * r;
  f.wait();
  return {{gr, yr + msg}, r};
}
// Computes the El Gamal Decryption Share on G1 in BLS12-381
G1 Participants::Participant::compute_decryption_share(const G1 &c1, const int &n, const int &id)
{
  // Is it faster to multiply both scalars first and then multiply with c1? Or use multithreading to calculate
  // lagrange_coeff in one thread and in the other already multiply c1 with secret and afterwards the result with the
  // lagrange_coeff?
  // save la_grange_coeffs beforehand and don't compute them all the time
  return c1 * (this->key_pair.secret * Polynomial::get_lagrange_coeff(BilinearGroup::BN(0), id, n));
}

G1 Participants::Participant::compute_decryption_share_without_lagrange(const G1 &c1)
{
  return c1 * this->key_pair.secret;
}

// Decrypts a ciphertext c2 with the composed shares of the participants and checks the size of c2
G1 Participants::Participant::decrypt(const G1 &composed_shares, const G1 &c2) { return c2 - composed_shares; }

// Simulates the mpc (used for debugging purposes only)
G1 Participants::simulate_mpc(std::vector<G1> shares)
{
  G1 composed_shares = G1::get_infty();
  for (int i = 0; i < shares.size(); i++)
  {
    composed_shares += shares[i];
  }
  return composed_shares;
}
