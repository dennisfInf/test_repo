
#pragma once
#include "networking/thread_channel/safe_queue.h"
#include "protos/bootstrap.grpc.pb.h"
#include <grpcpp/grpcpp.h>
namespace grpc
{

std::string build_address(const std::string &hostname, const int &port);

class BootstrapServiceImpl final : public bootstrapper::Bootstrap::Service
{
public:
  BootstrapServiceImpl(uint8_t n) : n(n), current_index(2) {}
  grpc::Status RegisterUser(grpc::ServerContext *context, const bootstrapper::Hello *request,
                            bootstrapper::ParticipantIndex *reply) override;
  bool pop_queue() { return queue.pop(); }
  bootstrapper::Participants get_participants() { return participants; }

private:
  bootstrapper::Participants participants;
  std::mutex participants_mutex;
  std::mutex current_index_mutex;
  uint8_t n;
  uint8_t current_index;
  SafeQueue<bool> queue;
};

class SendParticipantsServiceImpl final : public bootstrapper::SendParticipants::Service
{
public:
  SendParticipantsServiceImpl(uint8_t &n) : n(n) {}
  grpc::Status SendParticipants(grpc::ServerContext *context, const bootstrapper::Participants *request,
                                bootstrapper::Response *reply) override;
  bootstrapper::Participants pop_queue() { return queue.pop(); }

private:
  uint8_t &n;
  SafeQueue<bootstrapper::Participants> queue;
};

} // namespace grpc