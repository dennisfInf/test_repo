#include "crypto/schemes/threshold_el_gamal/protocol.h"
#include "crypto/bilinear_group/serializer.h"
#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/secret_sharing/share.h"
#include "crypto/schemes/threshold_el_gamal/helpers.h"
#include "networking/client.h"
#include "networking/grpc/dkg.h"
#include "networking/grpc/el_gamal.h"
#include "networking/grpc/serialize.h"
#include "networking/server.h"
#include "protos/threshold_el_gamal.grpc.pb.h"
#include <iostream>

namespace TEG
{

  Protocol init_protocol(const uint8_t &n, const uint8_t &t, const uint8_t &index,
                         std::vector<Networking::Client> &participants, std::map<std::string, grpc::Service *> &services)
  {
    // Hard-coded context string, should be changed
    std::string context = "context";
    TEG::Protocol proc = TEG::Protocol(participants, n, index, context);
    grpc::DKGServiceImpl *dkgService = Networking::cast_service<grpc::DKGServiceImpl>(services, "dkg");
    proc.run_dkg(dkgService, n, t);
    proc.get_public_key().precompute();
    return proc;
  }

  void Protocol::run_dkg(grpc::DKGServiceImpl *service, const uint8_t &n, const uint8_t &t)
  {
    std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> poly =
        secret_sharing.init(n, t, my_index, context);
    send_commited_shares(poly);
    Participants::Com_Shares my_share =
        Participants::Com_Shares{std::get<0>(poly).own_commitment(), std::get<1>(poly)[my_index - 1]};
    for (int i = 0; i < n; i++)
    {
      if (i == my_index - 1)
      {
        secret_sharing.add_com_share(my_share, my_index - 1);
        continue;
      }
      el_gamal::Commited_Share com_share = service->pop_queue();
      secret_sharing.add_com_share(Participants::handleCommittedShare(com_share, context, my_index), i);
    }

    Participants::KeyPair key_pair = secret_sharing.finalize(n);
    this->participant = Participants::Participant(key_pair);
  }

  void Protocol::send_commited_shares(
      std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> poly)
  {

    Commitments::DKG_Proposed_Commitments coms = std::get<0>(poly);
    std::vector<Participants::Share> shares = std::get<1>(poly);
    el_gamal::Proposed_Commitment coms_proto =
        coms.serialize_to_proto<el_gamal::Proposed_Commitment, el_gamal::Signature>();
    int share_index = 0;
    for (int i = 0; i < this->participants.size(); i++)
    {
      el_gamal::Commited_Share comm_share;
      comm_share.mutable_commitment()->CopyFrom(coms_proto);
      if (i == my_index - 1)
      {
        share_index++;
      }
      comm_share.mutable_share()->CopyFrom(shares[share_index].serialize_to_proto<el_gamal::Share>());
      Networking::Stub<el_gamal::DKG> stub = this->participants[i].createStub<el_gamal::DKG>();
      stub.send<el_gamal::Commited_Share, el_gamal::Response>(
          comm_share, comm_share.share().receiver_index(),
          [](el_gamal::DKG::Stub *stub, grpc::ClientContext *context, el_gamal::Commited_Share *request,
             el_gamal::Response *response)
          {
            grpc::Status status = stub->Send_Commited_Shares(context, *request, response);
            return status;
          });
      share_index++;
    }
  }

  DecryptionShare Protocol::share_c1_and_get_decryption_share(Participants::ciphertext &ciphertext, GS::zkp::GS_Proof &proof, uint8_t &t)
  {
    el_gamal::Ciphertext c_serialized;
    int ciphertext_id = this->receive_ciphertext_id();
    c_serialized.set_c1(grpc::serialize_to_string(ciphertext.c1));
    c_serialized.set_c2(grpc::serialize_to_string(ciphertext.c2));
    c_serialized.set_ciphertext_id(ciphertext_id);
    std::vector<uint8_t> buffer;
    BilinearGroup::Serializer serializer(buffer);
    serializer << proof;
    std::string str(buffer.begin(), buffer.end());
    c_serialized.set_nizk_proof(str);
    for (int i = 0; i < this->participants.size(); i++)
    {
      Networking::Stub<el_gamal::TEG> stub = this->participants[i].createStub<el_gamal::TEG>();
      stub.send<el_gamal::Ciphertext, el_gamal::Response>(c_serialized, i + 1,
                                                          [](el_gamal::TEG::Stub *stub, grpc::ClientContext *context,
                                                             el_gamal::Ciphertext *request, el_gamal::Response *response)
                                                          {
                                                            grpc::Status status =
                                                                stub->InitDecryption(context, *request, response);
                                                            return status;
                                                          });
    }
    return {ciphertext_id, participant.compute_decryption_share(ciphertext.c1, t + 1, my_index)};
  }

  DecryptionShare Protocol::share_c1_and_get_decryption_share_mal(Participants::ciphertext &ciphertext, GS::zkp::GS_Proof &proof, uint8_t &t)
  {
    el_gamal::Ciphertext c_serialized;
    int ciphertext_id = this->receive_ciphertext_id();
    c_serialized.set_c1(grpc::serialize_to_string(ciphertext.c1));
    c_serialized.set_c2(grpc::serialize_to_string(ciphertext.c2));
    c_serialized.set_ciphertext_id(ciphertext_id);
    std::vector<uint8_t> buffer;
    BilinearGroup::Serializer serializer(buffer);
    serializer << proof;
    std::string str(buffer.begin(), buffer.end());
    c_serialized.set_nizk_proof(str);

    for (int i = 0; i < this->participants.size(); i++)
    {
      Networking::Stub<el_gamal::TEG> stub = this->participants[i].createStub<el_gamal::TEG>();
      stub.send<el_gamal::Ciphertext, el_gamal::Response>(c_serialized, i + 1,
                                                          [](el_gamal::TEG::Stub *stub, grpc::ClientContext *context,
                                                             el_gamal::Ciphertext *request, el_gamal::Response *response)
                                                          {
                                                            grpc::Status status =
                                                                stub->InitDecryption(context, *request, response);
                                                            return status;
                                                          });
    }
    return {ciphertext_id, participant.compute_decryption_share_without_lagrange(ciphertext.c1)};
  }

  void Protocol::share_point(BilinearGroup::G1 &point)
  {
    el_gamal::Ciphertext c_serialized;
    int ciphertext_id = this->receive_ciphertext_id();
    c_serialized.set_c1(grpc::serialize_to_string(point));
    c_serialized.set_c2(grpc::serialize_to_string(point));
    c_serialized.set_ciphertext_id(my_index);
    std::vector<uint8_t> buffer;
    BilinearGroup::Serializer serializer(buffer);
    std::string str(buffer.begin(), buffer.end());
    c_serialized.set_nizk_proof(str);

    Networking::Stub<el_gamal::TEG> stub = this->participants[0].createStub<el_gamal::TEG>();
    stub.send<el_gamal::Ciphertext, el_gamal::Response>(c_serialized, 1,
                                                        [](el_gamal::TEG::Stub *stub, grpc::ClientContext *context,
                                                           el_gamal::Ciphertext *request, el_gamal::Response *response)
                                                        {
                                                          grpc::Status status =
                                                              stub->InitDecryption(context, *request, response);
                                                          return status;
                                                        });
  }

  el_gamal::Ciphertext Protocol::receive_ciphertext(grpc::TEGServiceImpl *service) { return service->pop_queue(); }

  DecryptionShare Protocol::calc_decryption_share(BilinearGroup::G1 &c1, int &ciphertext_id, uint8_t &t)
  {
    return {ciphertext_id,
            this->participant.compute_decryption_share(c1, t + 1, my_index)};
  }

  DecryptionShare Protocol::calc_decryption_share_wo_lagrange(BilinearGroup::G1 &c1, int &ciphertext_id)
  {
    return {ciphertext_id, this->participant.compute_decryption_share_without_lagrange(c1)};
  }
  int Protocol::receive_ciphertext_id()
  {
    std::lock_guard<std::mutex> lock(*this->ciphertext_id_mtx);
    int _ciphertext_id = this->ciphertext_id;
    this->ciphertext_id++;
    return _ciphertext_id;
  }

} // namespace TEG