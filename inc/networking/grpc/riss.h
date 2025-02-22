#pragma once
#include "networking/thread_channel/safe_queue.h"
#include "protos/riss.grpc.pb.h"
#include <grpcpp/grpcpp.h>

namespace grpc
{

class RISSServiceImpl final : public riss::RISS::Service
{
public:
  RISSServiceImpl(){};
  grpc::Status SendShare(grpc::ServerContext *context, const riss::Share *request, riss::Response *reply) override;
  grpc::Status SendR(grpc::ServerContext *context, const riss::R *request, riss::Response *reply) override;
  grpc::Status SendShamirShare(grpc::ServerContext *context, const riss::ShamirShare *request,
                               riss::Response *reply) override;
  riss::Share share_queue_pop() { return share_queue.pop(); }
  riss::ShamirShare shamir_share_queue_pop() { return shamir_share_queue.pop(); }
  riss::R r_queue_pop() { return r_queue.pop(); }

private:
  std::mutex seen_mutex;
  SafeQueue<riss::Share> share_queue;
  SafeQueue<riss::ShamirShare> shamir_share_queue;
  SafeQueue<riss::R> r_queue;
};
} // namespace grpc