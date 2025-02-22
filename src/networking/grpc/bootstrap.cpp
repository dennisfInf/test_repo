#include "networking/grpc/bootstrap.h"

namespace grpc
{

std::string build_address(const std::string &hostname, const int &port)
{
  std::stringstream ss;
  ss << hostname << ":" << port;
  return ss.str();
}

//This method is called, when the other operators send a hello message to the bootstrapper service.
//The bootstrapper then extracts the ip from the metadata and adds the participant to the list of participants with the transmitted port.
grpc::Status BootstrapServiceImpl::RegisterUser(grpc::ServerContext *context, const bootstrapper::Hello *request,
                                                bootstrapper::ParticipantIndex *reply)
{
  {
    const std::multimap<grpc::string_ref, grpc::string_ref> metadata = context->client_metadata();
    std::string client_ip;
    // insecure IP retrieval, should be signed. But since we are in a semi-honest setting, this works for now
    std::string peer = context->peer(); // e.g., "ipv4:192.168.1.1:50051"

    // Find the start of the IP address by finding the position of the first ':' and adding 1
    size_t start = peer.find(':') + 1;

    // Find the end of the IP address by finding the position of the last ':'
    size_t end = peer.rfind(':');

    // Extract the IP address
    client_ip = peer.substr(start, end - start);

    bootstrapper::Participant participant;

    std::string client_address = build_address(client_ip, request->port());
    participant.set_address(client_address);
    {
      std::lock_guard<std::mutex> lock(this->participants_mutex);
      // not a secure check (used for debugging), use for example certificates for authentication
      for (const auto &part : this->participants.participants())
      {
        if (part.address() == client_address)
        {
          // This client has already registered
          std::string error = "Client has already registered" + client_address;
          return grpc::Status(grpc::StatusCode::ALREADY_EXISTS, error);
        }
      }
      {
        {
          std::lock_guard<std::mutex> lock(this->current_index_mutex);
          // Set the fields of the Participant
          participant.set_index(this->current_index);
          if (this->current_index == n)
          {
            this->queue.push(true);
          }
          this->current_index++;
        }
      }
      bootstrapper::Participant *new_participant = this->participants.add_participants();
      new_participant->CopyFrom(participant);
    }
    reply->set_index(participant.index());
  }
  return grpc::Status::OK;
}

//Sends the participants to the other operators.
grpc::Status SendParticipantsServiceImpl::SendParticipants(grpc::ServerContext * /* context */,
                                                           const bootstrapper::Participants *request,
                                                           bootstrapper::Response * /* reply */)
{
  if (request->participants().size() != this->n - 2) // -2 because the bootstrapper and self are not included
  {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Number of participants does not match");
  }
  this->queue.push(*request);
  return grpc::Status::OK;
}
} // namespace grpc