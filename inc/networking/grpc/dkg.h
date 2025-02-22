#pragma once
#include "networking/thread_channel/safe_queue.h"
#include "protos/threshold_el_gamal.grpc.pb.h"
#include <grpcpp/grpcpp.h>

namespace grpc
{

  class DKGServiceImpl final : public el_gamal::DKG::Service
  {
  public:
    DKGServiceImpl(uint8_t max_amount) : max_amount(max_amount - 1) {}
    grpc::Status Send_Commited_Shares(grpc::ServerContext *context, const el_gamal::Commited_Share *request,
                                      el_gamal::Response *reply) override;
    el_gamal::Commited_Share pop_queue() { return commited_share_queue.pop(); }
    grpc::Status Send_Participant_PK(grpc::ServerContext *context, const el_gamal::Participant_Public_Key *request,
                                     el_gamal::Response *reply) override;
    el_gamal::Participant_Public_Key pop_pk_queue() { return participant_pk_queue.pop(); }

  private:
    uint8_t max_amount;
    uint8_t seen = 0;
    uint8_t seen_pk = 0;
    std::mutex seen_mutex;
    std::mutex seen_pk_mutex;

    SafeQueue<el_gamal::Commited_Share> commited_share_queue;
    SafeQueue<el_gamal::Participant_Public_Key> participant_pk_queue;
  };
} // namespace grpc