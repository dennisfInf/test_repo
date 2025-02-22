#pragma once
#include "networking/thread_channel/safe_queue.h"
#include "protos/tsps.grpc.pb.h"

namespace grpc
{

class TSPServiceImpl final : public tsps::DKG::Service
{
public:
  TSPServiceImpl(int max_amount, int l, int k) : max_amount((max_amount - 1) * l * k) {}
  grpc::Status Send_Commited_Shares(grpc::ServerContext *context, const tsps::Commited_Share *request,
                                    tsps::Response *reply) override;
  tsps::Commited_Share pop_queue() { return commited_share_queue.pop(); }
  tsps::Matrix pop_matrix_queue() { return matrix_queue.pop(); }
    tsps::Matrix pop_verify_key_queue() { return verification_key_queue.pop(); }

  tsps::Message pop_message_queue() { return message_queue.pop(); }
    tsps::PartialSignatureProto pop_partial_signature_queue() { return partial_signature_queue.pop(); }
  grpc::Status Send_Matrix(grpc::ServerContext *context, const tsps::Matrix *request, tsps::Response *reply) override;
  grpc::Status Send_Verification_Key(grpc::ServerContext *context, const tsps::Matrix *request, tsps::Response *reply) override;
  grpc::Status Send_Message(grpc::ServerContext *context, const tsps::Message *request, tsps::Response *reply) override;
  grpc::Status Send_PartialSignature(grpc::ServerContext *context, const tsps::PartialSignatureProto *request,
                                     tsps::Response *reply) override;

private:
  int max_amount;
  int seen = 0;
  std::mutex seen_mutex;
  SafeQueue<tsps::Commited_Share> commited_share_queue;
  SafeQueue<tsps::Matrix> matrix_queue;
    SafeQueue<tsps::Matrix> verification_key_queue;
  int seen_verify_keys = 0;
  std::mutex seen_verify_mutex;

  SafeQueue<tsps::Message> message_queue;
  SafeQueue<tsps::PartialSignatureProto> partial_signature_queue;

  int seen_public_parameters = 0;
  std::mutex seen_public_parameters_mutex;
};
} // namespace grpc