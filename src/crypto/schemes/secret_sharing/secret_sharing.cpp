#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include <iostream>

namespace Participants
{
  std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Share>>
  SecretSharing::init(const uint8_t &n, const uint8_t &t, const uint8_t &id, std::string &context)
  {
    uint8_t num_coefficients = t;
    std::vector<BilinearGroup::BN> polynomial = Polynomial::generate_polynomial(num_coefficients);
    BilinearGroup::BN secret = BilinearGroup::BN::rand();
    using namespace Commitments;
    std::vector<BilinearGroup::G1> commitments;

    std::future<void> f =
        BilinearGroup::pool.push([&commitments, &secret, &polynomial, &t](int)
                                 { commitments = Commitments::generate_commitments(secret, polynomial, t); });

    std::vector<Share> shares = Polynomial::evaluate_polynomial(polynomial, n, secret);

    BilinearGroup::BN r = BilinearGroup::BN::rand();
    BilinearGroup::G1 r_commitment = BilinearGroup::G1::get_gen() * r;
    f.wait();
    BilinearGroup::G1 secret_commitment = commitments[0];

    BilinearGroup::BN challenge = Commitments::generate_challenge(id, context, secret_commitment, r_commitment);

    BilinearGroup::BN response = r + challenge * secret;
    return {Commitments::DKG_Proposed_Commitments(id, commitments, Commitments::Signature{r_commitment, response}),
            shares};
  }

  KeyPair SecretSharing::finalize(const uint8_t &n)
  {
    KeyPair key_pair;
    key_pair.secret = get_secret(n);
    key_pair.secret_pub = BilinearGroup::G1::get_gen() * key_pair.secret;
    key_pair.group_public = BilinearGroup::G1::get_infty();
    key_pair.participants_pubs.resize(com_shares.size());
    // To Do: could do chunking for parallelization
    for (int i = 0; i < com_shares.size(); i++)
    {
      key_pair.group_public = key_pair.group_public + com_shares[i].commitment.commitments[0];
    };

    return key_pair;
  }

  BilinearGroup::BN SecretSharing::get_secret(const uint8_t &n)
  {
    if (com_shares.size() != n)
    {
      throw std::invalid_argument("Number of shares does not match number of participants");
    }
    BilinearGroup::BN secret = BilinearGroup::BN(0);
    // To Do: could do chunking for parallelization

    for (int i = 0; i < com_shares.size(); i++)
    {
      secret = com_shares[i].share + secret;
    }
    return secret;
  }
  void SecretSharing::add_com_share(const Participants::Com_Shares &com_share, const uint8_t &i)
  {
    this->com_shares[i] = com_share;
  }

  void ThreadSafeSecretSharing::add_com_share(const Participants::Com_Shares &com_share)
  {
    std::lock_guard<std::mutex> lock(this->mtx);

    this->SecretSharing::add_com_share(com_share, current_index);
    this->current_index++;
  }

  bool ThreadSafeSecretSharing::received_enough_shares(const uint8_t n)
  {
    if (current_index >= n)
    {
      return true;
    }
    else
    {
      return false;
    }
  }

  void SecretSharing::sendParticipantPublicKey(std::vector<Networking::Client> &clients, uint8_t &player_id, BilinearGroup::G1 &public_key)
  {
    el_gamal::Participant_Public_Key pk;
    pk.set_player_id(player_id);
    pk.set_pk(grpc::serialize_to_string(public_key));
    int share_index = 0;
    for (int i = 0; i < clients.size(); i++)
    {
      Networking::Stub<el_gamal::DKG> stub = clients[i].createStub<el_gamal::DKG>();
      stub.send<el_gamal::Participant_Public_Key, el_gamal::Response>(
          pk, i,
          [](el_gamal::DKG::Stub *stub, grpc::ClientContext *context, el_gamal::Participant_Public_Key *request,
             el_gamal::Response *response)
          {
            grpc::Status status = stub->Send_Participant_PK(context, *request, response);
            return status;
          });
      share_index++;
    }
  };
  void SecretSharing::receiveParticipantPublicKeys(KeyPair &key_pair, const uint8_t &n, grpc::DKGServiceImpl *service)
  {
    for (int i = 0; i < n - 1; i++)
    {
      el_gamal::Participant_Public_Key pk_serialized = service->pop_pk_queue();
      key_pair.participants_pubs[pk_serialized.player_id()] = grpc::deserialize_from_string<BilinearGroup::G1>(pk_serialized.pk())[0]; // Deserialize
    }
  };
  void polynomial_test(int n, int t)
  {
    std::cout << "testing polynomial with t: " << t << "and n: " << n << std::endl;
    BilinearGroup::BN secret = BilinearGroup::BN::rand();
    std::vector<BilinearGroup::BN> coefficients;
    for (int i = 0; i < t; i++)
    {
      coefficients.push_back(BilinearGroup::BN::rand());
    }
    std::vector<BilinearGroup::BN> y_coords;

    for (int i = 1; i <= n; i++)
    {
      y_coords.push_back(Polynomial::Horners_method<BilinearGroup::BN>(coefficients, BilinearGroup::BN(i),
                                                                       BilinearGroup::BN(0), coefficients.size(), 0) +
                         secret);
    }
    BilinearGroup::BN result;
    for (int i = 0; i < t; i++)
    {
      result += (y_coords[i] * Polynomial::get_lagrange_coeff(0, i + 1, t + 1));
    }
    if (result == secret)
    {
      std::cout << " check with t points successful" << std::endl;
    }
    else
    {
      std::cout << " check with t points failed" << std::endl;
    }
    BilinearGroup::BN result2;
    for (int i = 0; i < t + 1; i++)
    {
      result2 += (y_coords[i] * Polynomial::get_lagrange_coeff(0, i + 1, t + 1));
    }
    if (result2 == secret)
    {
      std::cout << " check with t+1 points successful" << std::endl;
    }
    else
    {
      std::cout << " check with t+1 points failed" << std::endl;
    }
    BilinearGroup::BN result3;
    for (int i = 0; i < n; i++)
    {
      result3 += (y_coords[i] * Polynomial::get_lagrange_coeff(0, i + 1, t + 1));
    }
    if (result3 == secret)
    {
      std::cout << " check with n points successful" << std::endl;
    }
    else
    {
      std::cout << " check with n  points failed" << std::endl;
    }
  }
  void try_reconstruct_secret(std::vector<KeyPair> key_pairs, int n, int t)
  {
    BilinearGroup::G1 group_public = key_pairs[0].group_public;
    BilinearGroup::BN secret;
    for (int i = 0; i < t; i++)
    {
      secret = secret + key_pairs[i].secret * Polynomial::get_lagrange_coeff(0, i + 1, n);
    }
    if (BilinearGroup::G1::get_gen() * secret == group_public)
    {
      std::cout << "secret reconstructed with t: " << t << "and n: " << n << std::endl;
    }
    else
    {
      std::cout << "secret not reconstructed with t: " << t << "and n: " << n << std::endl;
    }
  }

  void test_secret_sharing(int n, int t)
  {
    polynomial_test(n, t);
    SecretSharing secret_sharing = SecretSharing(n);
    std::vector<SecretSharing> secret_sharings(n, secret_sharing);
    std::string context = "test";
    int participant_int = 0;
    for (auto participant : secret_sharings)
    {
      auto [commitments, shares] = participant.init(n, t, 0, context);
      for (int i = 0; i < n; i++)
      {
        Com_Shares commited_shares;
        std::optional<Commitments::DKG__Commitment> dkg_com = commitments.verify(context);

        if (dkg_com.has_value())
        {

          commited_shares.commitment = dkg_com.value();

          if (shares[i].verify(commited_shares.commitment, i + 1))
          {
            commited_shares.share = shares[i];
          }
          else
          {
            std::cout << "invalid share" << std::endl;
            exit(1);
          }
          secret_sharings[i].add_com_share(commited_shares, participant_int);
        }
        else
        {
          std::cout << "commitment with index is invalid" << std::endl;
          exit(1);
        }
      }
      participant_int++;
    }
    std::vector<KeyPair> key_pairs;
    for (auto participant : secret_sharings)
    {
      key_pairs.push_back(participant.finalize(n));
    }
    for (int i = 1; i < n; i++)
    {
      if (key_pairs[i].group_public != key_pairs[i - 1].group_public)
      {
        throw std::invalid_argument("group public keys do not match");
      }
    }
    for (int i = t; i <= n; i++)
    {
      try_reconstruct_secret(key_pairs, n, i);
    }
  }

}; // namespace Participants
