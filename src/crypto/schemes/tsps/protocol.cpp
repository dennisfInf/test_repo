#include "crypto/schemes/tsps/protocol.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "crypto/schemes/tsps/matrix_serializer.h"
#include "crypto/schemes/tsps/setup.h"
#include "crypto/schemes/tsps/sign.h"
#include "crypto/schemes/tsps/verify.h"
#include "networking/grpc/serialize.h"
#include "networking/grpc/tsps.h"
#include "networking/server.h"
#include "networking/thread_channel/safe_queue.h"

namespace tsps
{

  void Protocol::receive_matrix(SafeQueue<bool> &queue)
  {
    std::vector<std::future<void>> futures;

    for (int i = 0; i < public_parameters_size(); i++)
    {
      futures.push_back(BilinearGroup::pool.push(
          [this, &queue](int)
          {
            tsps::Matrix matrix = this->service->pop_matrix_queue();
            switch (matrix.matrix_variant())
            {
            case 0:
              this->pp.A = deserialize_from_proto<BilinearGroup::G2>(matrix.matrix(), k + 1, k);
              this->pp.A.precompute();
              queue.push(true);
              break;
            case 1:
              this->pp.UA = deserialize_from_proto<BilinearGroup::G2>(matrix.matrix(), k + 1, k);
              this->pp.UA.precompute();
              break;
            case 2:
              this->pp.VA = deserialize_from_proto<BilinearGroup::G2>(matrix.matrix(), k + 1, k);
              this->pp.VA.precompute();
              break;
            case 3:
              this->pp.B = deserialize_from_proto<BilinearGroup::G1>(matrix.matrix(), k + 1, k);
              this->pp.B.precompute();
              break;
            case 4:
              this->pp.BtU = deserialize_from_proto<BilinearGroup::G1>(matrix.matrix(), k, k + 1);
              this->pp.BtU.precompute();
              break;
            case 5:
              this->pp.BtV = deserialize_from_proto<BilinearGroup::G1>(matrix.matrix(), k, k + 1);
              this->pp.BtV.precompute();
              break;
            default:
              throw std::runtime_error("Unknown matrix variant");
            };
          }));
    }
    for (auto &f : futures)
    {
      f.wait();
    }
  }

  void Protocol::receive_verification_keys()
  {
    std::vector<std::future<void>> futures;

    for (int i = 0; i < n - 1; i++)
    {
      futures.push_back(BilinearGroup::pool.push(
          [this](int)
          {
            tsps::Matrix matrix = this->service->pop_verify_key_queue();
            this->key.add_verification_key(deserialize_from_proto<BilinearGroup::G2>(matrix.matrix(), l + 1, k),
                                           matrix.matrix_variant(), n);
          }));
    }
    for (auto &f : futures)
    {
      f.wait();
    }
    this->get_public_key().precompute();
  }

  void Protocol::init(bool &bootstrapper)
  {
    if (bootstrapper)
    {
      std::future<void> future = BilinearGroup::pool.push([this](int)
                                                          { this->pp = create_public_params(this->k); });
      BilinearGroup::pool.push(
          [this, &future](int)
          {
            future.wait();
            this->send_public_parameters();
          });
      this->run_dkg();
      future.wait();
      this->key.set_public_share(pp.A, this->my_index, this->n);
      this->send_verification_key();
      // can be done in parallel

      this->receive_verification_keys();
    }
    else
    {
      SafeQueue<bool> queue;
      std::future<void> future = BilinearGroup::pool.push([this, &queue](int)
                                                          { this->receive_matrix(queue); });
      this->run_dkg();
      queue.pop();

      this->key.set_public_share(pp.A, this->my_index, this->n);
      this->send_verification_key();
      this->receive_verification_keys();
        
      future.wait();
      if (this->t + 1 >= my_index)
      {
        BilinearGroup::pool.push([this](int)
                                 { this->receive_messages(); });
      }
    }
  }
  tsps::SignatureM Protocol::sign_message(std::vector<BilinearGroup::G1> &message, int message_id, GS::u_reg::GS_Proof &user_proof)
  {
    std::string message_string = serialize_to_proto(message);
    tsps::Message tsps_message;
    tsps_message.set_message(message_string);
    tsps_message.set_id(message_id);
    std::vector<uint8_t> buffer;
    BilinearGroup::Serializer serializer(buffer);
    serializer << user_proof;
    std::string str(buffer.begin(), buffer.end());
    tsps_message.set_nizk_proof(str);
    for (int i = 0; i < t; i++)
    {
      BilinearGroup::pool.push(
          [this, tsps_message, i](int)
          {
            this->send_message(tsps_message, i);
          });
    }
    PartialSignature partial_sig = this->partial_sign_message(message);
    return receive_partial_signatures(partial_sig, message, message_id);
  }

  PartialSignature Protocol::partial_sign_message(std::vector<BilinearGroup::G1> &m)
  {

    SignatureM signature = parSign(this->pp, this->key.get_secret_share(), m);
    /*   if (verify(this->pp, m, this->key.get_public_share(), signature))
      {
        std::cout << "par signature verified" << std::endl;
      }
      else
      {
        std::cout << "par signature not verified" << std::endl;
      } */
    return {this->my_index, signature};
  }
  void Protocol::send_message(tsps::Message tsps_message, const int &participant_index)
  {
    auto start = std::chrono::high_resolution_clock::now();

    Networking::Stub<tsps::DKG> stub = participants[participant_index].createStub<tsps::DKG>();
    stub.send<tsps::Message, tsps::Response>(
        tsps_message, participant_index,
        [](tsps::DKG::Stub *stub, grpc::ClientContext *context, tsps::Message *request, tsps::Response *response)
        {
          grpc::Status status = stub->Send_Message(context, *request, response);
          return status;
        });
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_ce = end - start;
    std::cout << "send message time: " << elapsed_ce.count() << " seconds for: " << participant_index << std::endl;
  }

  void Protocol::send_partial_signature(const PartialSignature &partial_signature, const int &message_id)
  {
    tsps::PartialSignatureProto proto_partial_signature;
    proto_partial_signature.set_message_id(message_id);
    proto_partial_signature.set_party_id(this->my_index);

    proto_partial_signature.set_sig_1(serialize_to_proto(partial_signature.signature.sig_1.to_vector()));
    proto_partial_signature.set_sig_2(serialize_to_proto(partial_signature.signature.sig_2.to_vector()));
    proto_partial_signature.set_sig_3(serialize_to_proto(partial_signature.signature.sig_3.to_vector()));
    proto_partial_signature.set_sig_4(grpc::serialize_to_string(partial_signature.signature.sig_4));
    Networking::Stub<tsps::DKG> stub = participants[0].createStub<tsps::DKG>();
    stub.send<tsps::PartialSignatureProto, tsps::Response>(
        proto_partial_signature, 0,
        [](tsps::DKG::Stub *stub, grpc::ClientContext *context, tsps::PartialSignatureProto *request,
           tsps::Response *response)
        {
          grpc::Status status = stub->Send_PartialSignature(context, *request, response);
          return status;
        });
  }

  void Protocol::receive_messages()
  {
    for (int i = 0; i < runs; i++)
    {
      std::cout << "message queue " << i << std::endl;
      tsps::Message message = this->service->pop_message_queue();
      std::vector<BilinearGroup::G1> message_vec =
          grpc::deserialize_from_string<BilinearGroup::G1>(message.message());
      GS::u_reg::GS_Proof user_proof;
      std::string proof_str = message.nizk_proof();
      std::vector<uint8_t> buffer(proof_str.begin(), proof_str.end());
      BilinearGroup::Deserializer deserializer(buffer);
      deserializer >> user_proof;
      GS::u_reg::GS_Input_Public public_input;
      public_input.pk = {message_vec[1]};
      // ZKP check should be moved to home operators class and verified there
      auto start_verify_proof = std::chrono::high_resolution_clock::now();
      std::cout << "verifying batch proof" << std::endl;
      if (!GS::u_reg::batch_verify(this->crs_nizk, user_proof, public_input))
      {
        throw std::invalid_argument("zkp not verified in register user");
      }
      auto end_verify_proof = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double> elapsed_verify_proof = end_verify_proof - start_verify_proof;
      std::cout << "tsps part sign nizk time: " << elapsed_verify_proof.count() << " seconds" << std::endl;
      PartialSignature signature = partial_sign_message(message_vec);
      this->send_partial_signature(signature, message.id());
    }
  }

  tsps::SignatureM Protocol::receive_partial_signatures(tsps::PartialSignature &partial_sig, std::vector<BilinearGroup::G1> &message_vec, int &message_id)
  {
    int counter = 1;
    std::vector<PartialSignature> partial_sigs(t + 1);
    partial_sigs[0] = partial_sig;
    while (counter < t + 1)
    {
      tsps::PartialSignatureProto partial_signature = this->service->pop_partial_signature_queue();
      std::cout << "received partial sign" << std::endl;
      SignatureM signature;
      signature.sig_1 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_1(), 1, k + 1);
      signature.sig_2 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_2(), 1, k + 1);
      signature.sig_3 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_3(), 1, k + 1);
      signature.sig_4 = grpc::deserialize_from_string<BilinearGroup::G2>(partial_signature.sig_4())[0];
      PartialSignature partial_sig = {static_cast<uint8_t>(partial_signature.party_id()), signature};
      partial_sigs[counter] = partial_sig;
      counter++;
    }
    return verify_partial_signatures(partial_sigs, t + 1, message_vec, message_id);
  }

  tsps::SignatureM Protocol::verify_partial_signatures(std::vector<PartialSignature> &partial_sigs, uint8_t threshold, std::vector<BilinearGroup::G1> &message_vec, int &message_id)
  {
    SignatureM signature = combineSign(threshold, partial_sigs);
    if (verify(this->pp, message_vec, this->key.get_public_key(), signature))
    {
      std::lock_guard<std::mutex> lock(this->accounts_mtx);
      // hard-coded user info
      combined_signatures[message_id] = signature;
      accounts.push_back({message_vec[0], "dummy info"});
      std::cout << "threshold signature verified..." << std::endl;
      return signature;
    }
    else
    {
      std::cout << "signature not verified" << std::endl;
    }
    return signature;
  }
  /*   tsps::SignatureM Protocol::check_if_all_partial_sigs_received(
        std::pair<std::vector<BilinearGroup::G1>, std::vector<PartialSignature>> &partial_sigs, int id)
    {
      if (partial_sigs.second.size() > t && partial_sigs.first.size() > 0)
      {
        // To Do: remove all used partial signatures from the map
        uint8_t threshold = t + 1;
        SignatureM signature = combineSign(threshold, partial_sigs.second);
        if (verify(this->pp, partial_sigs.first, this->key.get_public_key(), signature))
        {
          std::lock_guard<std::mutex> lock(this->accounts_mtx);
          // hard-coded user info
          combined_signatures[id] = signature;
          accounts.push_back({partial_sigs.first[0], "dummy info"});
          std::cout << "threshold signature verified..." << std::endl;
          return signature;
        }
        else
        {
          std::cout << "signature not verified" << std::endl;
        }
      }
      return {};
    }; */

  void Protocol::send_verification_key()
  {
    BilinearGroup::pool.push(
        [this](int)
        {
          std::vector<std::future<void>> futures;
          tsps::Matrix tsps_matrix = serialize_to_proto(int(this->my_index), this->key.get_public_share());
          for (int i = 0; i < participants.size(); i++)
          {
            futures.push_back(BilinearGroup::pool.push(
                [this, i, &tsps_matrix](int)
                {
                  Networking::Stub<tsps::DKG> stub = participants[i].createStub<tsps::DKG>();
                  stub.send<tsps::Matrix, tsps::Response>(tsps_matrix, i,
                                                          [](tsps::DKG::Stub *stub, grpc::ClientContext *context,
                                                             tsps::Matrix *request, tsps::Response *response)
                                                          {
                                                            grpc::Status status =
                                                                stub->Send_Verification_Key(context, *request, response);
                                                            return status;
                                                          });
                }));
          }
          for (auto &f : futures)
          {
            f.wait();
          }
        });
  }

  std::variant<bool, SignatureM> Protocol::receive_combined_signature(int message_id)
  {
    auto start = std::chrono::steady_clock::now();
    std::chrono::seconds duration(10);
    while (std::chrono::steady_clock::now() - start < duration)
    {
      std::lock_guard<std::mutex> lock(this->accounts_mtx);
      auto it = combined_signatures.find(message_id);
      if (it != combined_signatures.end())
      {
        // key exists in the map
        return it->second;
        // now you can use the key and value
      }
    }
    std::cout << "combined signature not found returning empty struct..." << std::endl;
    return false;
  }

  tsps::SignatureM ProtocolMal::receive_partial_signatures(tsps::PartialSignature &partial_sig, std::vector<BilinearGroup::G1> &message_vec, int &message_id)
  {
    std::cout << "receiving partial sign" << std::endl;
    int counter = 1;
    std::vector<PartialSignature> partial_sigs(t + 1);
    partial_sigs[0] = partial_sig;
    while (counter < t + 1)
    {
      tsps::PartialSignatureProto partial_signature = this->service->pop_partial_signature_queue();
      std::cout << "received partial sign" << std::endl;
      SignatureM signature;
      signature.sig_1 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_1(), 1, k + 1);
      signature.sig_2 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_2(), 1, k + 1);
      signature.sig_3 = deserialize_from_proto<BilinearGroup::G1>(partial_signature.sig_3(), 1, k + 1);
      signature.sig_4 = grpc::deserialize_from_string<BilinearGroup::G2>(partial_signature.sig_4())[0];
      PartialSignature partial_sig = {static_cast<uint8_t>(partial_signature.party_id()), signature};
      std::cout << " part verification..." << std::endl;
      if (verify(this->pp, message_vec, this->key.get_public_shares()[partial_sig.party_id - 1], partial_sig.signature))
      {
        partial_sigs[counter] = partial_sig;
        counter++;
      }
      else
      {
        std::cout << "partial signature not valid" << std::endl;
        exit(1);
      }
    }
    return verify_partial_signatures(partial_sigs, t + 1, message_vec, message_id);
  }

} // namespace tsps