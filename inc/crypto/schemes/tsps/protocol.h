#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/secret_sharing/share.h"
#include "crypto/bookkeeping_proofs/u_reg/out_types.hpp"
#include "crypto/schemes/tsps/key_gen.h"
#include "crypto/schemes/tsps/matrix_dist.h"
#include "crypto/schemes/tsps/matrix_serializer.h"
#include "crypto/schemes/tsps/setup.h"
#include "crypto/schemes/tsps/sign.h"
#include "networking/client.h"
#include "networking/grpc/serialize.h"
#include "networking/grpc/tsps.h"
#include "networking/server.h"
#include "networking/thread_channel/safe_queue.h"

namespace tsps
{
  struct UserInfo
  {
    BilinearGroup::G1 pk_u;
    std::string info;
  };

  class Protocol
  {
  public:
    Protocol(std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t, const uint8_t &k,
             const uint8_t &l, const uint8_t &my_index, std::map<std::string, grpc::Service *> &services, GS::CRS crs_nizk, uint &runs)
        : t(t), k(k), key(l + 1, k + 1, n), participants(participants), n(n), l(l), my_index(my_index), crs_nizk(crs_nizk), runs(runs)
    {
      this->service = Networking::cast_service<grpc::TSPServiceImpl>(services, "tsps");
    }
    void init(bool &bootstrapper);
    tsps::SignatureM sign_message(std::vector<BilinearGroup::G1> &message, int message_id, GS::u_reg::GS_Proof &user_proof);
    std::variant<bool, SignatureM> receive_combined_signature(int message_id);
    int get_current_message_id()
    {
      int message_id;

      std::lock_guard<std::mutex> lock(this->mutex);

      message_id = this->current_message_id;
      this->current_message_id++;

      return message_id;
    }
    BilinearGroup::Matrix<BilinearGroup::G2> get_public_key() { return key.get_public_key(); };
    PublicParameters get_public_parameters() { return pp; };
    virtual tsps::SignatureM receive_partial_signatures(tsps::PartialSignature &partial_sig, std::vector<BilinearGroup::G1> &message_vec, int &message_id);

  protected:
    uint8_t t;
    uint8_t k;
    Key key;
    grpc::TSPServiceImpl *service;
    PublicParameters pp;
    tsps::SignatureM verify_partial_signatures(std::vector<PartialSignature> &partial_sigs, uint8_t threshold, std::vector<BilinearGroup::G1> &message_vec, int &message_id);

  private:
    PartialSignature partial_sign_message(std::vector<BilinearGroup::G1> &m);
    void run_dkg();
    void share_of_coefficient(const uint8_t &row, const uint8_t &column, std::string &context,
                              Participants::ThreadSafeSecretSharing &secret_sharing);
    void send_commited_shares(std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> &poly,
                              const uint8_t &row, const uint8_t &column);
    void send_public_parameters();
    void send_verification_key();

    template <typename T>
    void send_matrix(const int &matrix_variant, BilinearGroup::Matrix<T> &matrix, const int &participant_index)
    {
      tsps::Matrix tsps_matrix = serialize_to_proto(matrix_variant, matrix);
      Networking::Stub<tsps::DKG> stub = participants[participant_index].createStub<tsps::DKG>();
      stub.send<tsps::Matrix, tsps::Response>(
          tsps_matrix, participant_index,
          [](tsps::DKG::Stub *stub, grpc::ClientContext *context, tsps::Matrix *request, tsps::Response *response)
          {
            grpc::Status status = stub->Send_Matrix(context, *request, response);
            return status;
          });
    }
    void send_message(tsps::Message tsps_message, const int &participant_index);
    void send_partial_signature(const PartialSignature &partial_signature, const int &message_id);
    void receive_messages();
    void receive_matrix(SafeQueue<bool> &queue);
    void receive_verification_keys();
    std::vector<Networking::Client> &participants;
    uint8_t n;
    uint8_t l;
    std::mutex mutex;
    std::mutex map_mutex;
    int current_message_id;
    std::map<int, std::pair<std::vector<BilinearGroup::G1>, std::vector<PartialSignature>>>
        partial_signatures;                        // To Do: Could be more memory efficient by using two maps
    std::map<int, SignatureM> combined_signatures; // mapping addresses to combined signatures
    uint8_t my_index;
    // not a nice fix to include crs_nizk here, but works for now
    GS::CRS crs_nizk;
    std::vector<UserInfo> accounts;
    std::mutex accounts_mtx;
    uint runs;
  };

  class ProtocolMal : public Protocol
  {
  public:
    ProtocolMal(std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t, const uint8_t &k,
                const uint8_t &l, const uint8_t &my_index, std::map<std::string, grpc::Service *> &services, GS::CRS crs_nizk, uint &runs)
        : Protocol(participants, n, t, k, l, my_index, services, crs_nizk, runs) {
          };

  private:
    tsps::SignatureM receive_partial_signatures(tsps::PartialSignature &partial_sig, std::vector<BilinearGroup::G1> &message_vec, int &message_id) override;
  };
} // namespace tsps