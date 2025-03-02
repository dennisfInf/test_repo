#pragma once
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/threshold_el_gamal/participant.h"
#include "networking/client.h"
#include "networking/grpc/dkg.h"
#include "networking/grpc/el_gamal.h"
#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "participant.h"
namespace TEG
{
  struct DecryptionShare
  {
    int ciphertext_id;
    G1 share;
  };
  // namespace TEG
  class Protocol
  {
  public:
    Protocol(std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &my_index,
             const std::string context)
        : secret_sharing(n), participants(participants), my_index(my_index), context(context)
    {
      ciphertext_id = 0;
      ciphertext_id_mtx = std::make_shared<std::mutex>();
    };
    void share_point(BilinearGroup::G1 &point);
    void run_dkg(grpc::DKGServiceImpl *service, const uint8_t &n, const uint8_t &t);
    DecryptionShare share_c1_and_get_decryption_share(Participants::ciphertext &ciphertext, GS::zkp::GS_Proof &proof, uint8_t &t);
    virtual DecryptionShare calc_decryption_share(BilinearGroup::G1 &c1, int &ciphertext_id, uint8_t &t);
    DecryptionShare calc_decryption_share_wo_lagrange(BilinearGroup::G1 &c1, int &ciphertext_id);
    DecryptionShare share_c1_and_get_decryption_share_mal(Participants::ciphertext &ciphertext, GS::zkp::GS_Proof &proof, uint8_t &t);

    BilinearGroup::G1 get_public_key() { return participant.get_public_key(); }
    BilinearGroup::G1 get_participant_public_key() { return participant.get_public_key(); }
    el_gamal::Ciphertext receive_ciphertext(grpc::TEGServiceImpl *service);

  private:
    void send_commited_shares(std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> poly);
    Participants::Participant participant;
    Participants::SecretSharing secret_sharing;
    std::vector<Networking::Client> &participants;
    uint8_t my_index;
    std::string context;
    int ciphertext_id;
    std::shared_ptr<std::mutex> ciphertext_id_mtx;
    int receive_ciphertext_id();
  };

  class ProtocolForMal: public Protocol{

  };

  
  Protocol init_protocol(const uint8_t &n, const uint8_t &t, const uint8_t &index,
                         const std::vector<Networking::Client> &participants,
                         std::map<std::string, grpc::Service *> &services);

}; // namespace TEG