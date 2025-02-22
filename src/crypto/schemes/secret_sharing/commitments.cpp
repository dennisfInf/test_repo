#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/threshold_el_gamal/helpers.h"
#include "networking/grpc/serialize.h"

#include <iostream>

using namespace Commitments;

// Uses the secret and coefficients of the polynomial to generate Pedersen Commitments by multiplying them with the
// generator of G1
std::vector<BilinearGroup::G1> Commitments::generate_commitments(const BilinearGroup::BN &secret,
                                                                 const std::vector<BilinearGroup::BN> polynomial,
                                                                 const uint8_t &t)
{
  std::vector<BilinearGroup::G1> commitments;
  //could also use polynomial.size() + 1 (later work)
  commitments.resize(t+1);
  std::vector<std::future<void>> futures;
  futures.push_back(BilinearGroup::pool.push([&commitment = commitments[0], &secret](int)
                                             { commitment = BilinearGroup::G1::get_gen() * secret; }));
  for (int i = 0; i < polynomial.size(); i++)
  {
    futures.push_back(BilinearGroup::pool.push([&commitment = commitments[i + 1], &coefficient = polynomial[i]](int)
                                               { commitment = BilinearGroup::G1::get_gen() * coefficient; }));
  }
  for (auto &f : futures)
  {
    f.wait();
  }
  return commitments;
};

// Generates a challenge by hashing the secret commitment, r commitment, context and id
BilinearGroup::BN Commitments::generate_challenge(const uint8_t id, const std::string context,
                                                  const BilinearGroup::G1 secret_commitment,
                                                  const BilinearGroup::G1 r_commitment)
{
  uint8_t secret_commitment_size = secret_commitment.buffer_size();
  uint8_t r_commitment_size = r_commitment.buffer_size();
  uint8_t context_size = context.size();
  uint8_t *buffer = new uint8_t[secret_commitment_size + r_commitment_size + context_size + 1];
  std::vector<std::future<void>> futures;
  futures.push_back(BilinearGroup::pool.push(
      [buffer, &secret_commitment_size, &secret_commitment](int)
      {
        uint8_t *secret_commitment_buffer = new uint8_t[secret_commitment_size];
        secret_commitment.serialize(secret_commitment_buffer, secret_commitment_size);
        std::copy(secret_commitment_buffer, secret_commitment_buffer + secret_commitment_size, buffer);
        delete[] secret_commitment_buffer;
      }));

  futures.push_back(BilinearGroup::pool.push(
      [buffer, &r_commitment_size, &r_commitment, &secret_commitment_size](int)
      {
        uint8_t *r_commitment_buffer = new uint8_t[r_commitment_size];
        r_commitment.serialize(r_commitment_buffer, r_commitment_size);
        std::copy(r_commitment_buffer, r_commitment_buffer + r_commitment_size, buffer + secret_commitment_size);
        delete[] r_commitment_buffer;
      }));

  uint8_t *context_buffer = new uint8_t[context_size];
  std::copy(context.begin(), context.end(), context_buffer);
  uint8_t index_buffer = uint8_t(id);
  std::copy(context_buffer, context_buffer + context_size, buffer + secret_commitment_size + r_commitment_size);
  std::copy(&index_buffer, &index_buffer + 1, buffer + secret_commitment_size + r_commitment_size + context_size);
  for (auto &f : futures)
  {
    f.wait();
  }
  std::vector<uint8_t> challenge =
      BilinearGroup::hash(buffer, secret_commitment_size + r_commitment_size + context_size + 1);
  delete[] buffer;
  delete[] context_buffer;
  return BilinearGroup::BN::hash_to_group(challenge);
};

BilinearGroup::BN DKG_Proposed_Commitments::generate_challenge(const std::string &context)
{
  return Commitments::generate_challenge(this->player_id, context, this->commitments[0], this->zkp.r);
};

// verifies a schnorr signature
std::optional<DKG__Commitment> DKG_Proposed_Commitments::verify_zkp(const BilinearGroup::BN &challenge)
{
  BilinearGroup::G1 com_r = this->zkp.r;
  BilinearGroup::G1 pub_z;
  std::future<void> f =
      BilinearGroup::pool.push([this, &pub_z](int) { pub_z = BilinearGroup::G1::get_gen() * this->zkp.z; });
  BilinearGroup::G1 secret_commitment_challenge = this->commitments[0] * challenge;
  f.wait();
  if (com_r != pub_z - secret_commitment_challenge)
  {
    return {};
  }
  else
  {
    return DKG__Commitment{this->player_id, this->commitments};
  }
}
std::optional<Commitments::DKG__Commitment> DKG_Proposed_Commitments::verify(const std::string &context)
{
  BilinearGroup::BN challenge = this->generate_challenge(context);

  std::optional<Commitments::DKG__Commitment> verified_commitment = this->verify_zkp(challenge);

  return verified_commitment;
}

Commitments::DKG__Commitment DKG_Proposed_Commitments::own_commitment()
{
  return DKG__Commitment{this->player_id, this->commitments};
}