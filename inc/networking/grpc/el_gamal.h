#pragma once
#include "networking/thread_channel/safe_queue.h"
#include "protos/threshold_el_gamal.grpc.pb.h"
#include <grpcpp/grpcpp.h>

namespace grpc
{

class TEGServiceImpl final : public el_gamal::TEG::Service
{
public:
  TEGServiceImpl(){}
  grpc::Status InitDecryption(grpc::ServerContext *context, const el_gamal::Ciphertext *request,
                              el_gamal::Response *reply) override;
  el_gamal::Ciphertext pop_queue() { return ciphertext_queue.pop(); }

private:
  SafeQueue<el_gamal::Ciphertext> ciphertext_queue;
};
} // namespace grpc