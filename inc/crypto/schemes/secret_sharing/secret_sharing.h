#pragma once
#include "commitments.h"
#include "group.h"
#include "share.h"
#include "networking/client.h"
#include <iostream>
#include <vector>
#include <networking/grpc/dkg.h>

namespace Participants
{

  struct KeyPair
  {
    BilinearGroup::BN secret;
    BilinearGroup::G1 secret_pub;
    BilinearGroup::G1 group_public;
    std::vector<BilinearGroup::G1> participants_pubs;
  };

  class SecretSharing
  {
  public:
    SecretSharing() {};
    SecretSharing(const uint8_t &n) { this->com_shares = std::vector<Participants::Com_Shares>(n); };
    std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Share>> init(const uint8_t &n, const uint8_t &t,
                                                                               const uint8_t &id, std::string &context);
    KeyPair finalize(const uint8_t &n);
    BilinearGroup::BN get_secret(const uint8_t &n);
    void add_com_share(const Participants::Com_Shares &com_share, const uint8_t &i);
    const std::vector<Participants::Com_Shares> &getComShares() const { return com_shares; }
    void setComShares(const std::vector<Participants::Com_Shares> &new_com_shares) { com_shares = new_com_shares; }
    void sendParticipantPublicKey(std::vector<Networking::Client> &clients, uint8_t &player_id, BilinearGroup::G1 &public_key);
    void receiveParticipantPublicKeys(KeyPair &key_pair, const uint8_t &n, grpc::DKGServiceImpl *service);

  private:
    std::vector<Participants::Com_Shares> com_shares;
  };

  class ThreadSafeSecretSharing : public SecretSharing
  {
  public:
    ThreadSafeSecretSharing(const uint8_t &n) : SecretSharing(n) {};
    void add_com_share(const Participants::Com_Shares &com_share);
    ThreadSafeSecretSharing(const Participants::ThreadSafeSecretSharing &other) : SecretSharing()
    {
      this->setComShares(other.getComShares());
      this->current_index = other.current_index;
    }
    bool received_enough_shares(const uint8_t n);

  private:
    std::mutex mtx;
    int current_index = 0;
  };
  void test_secret_sharing(int n, int t);
}; // namespace Participants