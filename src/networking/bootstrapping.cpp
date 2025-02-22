#include "networking/bootstrapping.h"
#include "crypto/bilinear_group/deserializer.h"
#include "crypto/bilinear_group/serializer.h"
#include "crypto/bookkeeping_proofs/setup.h"
#include "networking/client.h"
#include "networking/grpc/bootstrap.h"
#include "networking/server.h"
#include "protos/bootstrap.grpc.pb.h"
#include <grpcpp/client_context.h>
#include <thread>
//This runs the bootstrapping process
namespace Networking
{
std::tuple<std::vector<Client>, uint8_t> run_bootsstrap(const bool &bootstrapper, const int &port_base,
                                                        const std::string bootstrap_address,
                                                        std::map<std::string, grpc::Service *> &services, GS::CRS &crs)
{
  //creates a bootstrapper, if this node is the bootstrapper
  if (bootstrapper)
  {
    //need to cast the service to the correct type
    grpc::BootstrapServiceImpl *bootstrapService =
        Networking::cast_service<grpc::BootstrapServiceImpl>(services, "bootstrap");
    //generates a crs for the NIZK. For simplicity, this is done by only the bootstrapper. Also this does not affect our benchmarks.
    crs = GS::zkp::generate_crs();
    return create_bootstrapper(bootstrapService, crs);
  }
  else
  {
    if (bootstrap_address == "")
    {
      std::cout << "Bootstrap IP not provided" << std::endl;
      exit(1);
    }
     //creates a client to the bootstrapper service
    grpc::SendParticipantsServiceImpl *sendParticipantsService =
        Networking::cast_service<grpc::SendParticipantsServiceImpl>(services, "send_participants");
    return create_bootstrap_client(bootstrap_address, port_base, sendParticipantsService, crs);
  }
}
//This method creates a vector of clients from the participants. Clients are used to send messages to the grpc services of the participants
std::vector<Client> create_clients(const bootstrapper::Participants &participants)
{
  std::vector<Client> clients;

  clients.resize(participants.participants_size());
  for (int i = 0; i < participants.participants_size(); i++)
  {
    clients[i] = Client(participants.participants(i).address(), participants.participants(i).index());
  }
  return clients;
}


std::tuple<std::vector<Client>, uint8_t> create_bootstrapper(grpc::BootstrapServiceImpl *service, GS::CRS &crs)
{
  //this accesses the queue of the service. All other participants are sending a hello message to this bootstrapper service.
  // A result is enqueued to this queue, if all participants have sent a hello message.
  bool result = service->pop_queue();
  if (result)
  {
    //This gets all participant's that connected to the bootstrapper service. 
    bootstrapper::Participants participants = service->get_participants();
    std::vector<Client> clients = create_clients(participants);
    //Serializes the crs and sends the list of participants to all participants. This also includes a unique index for each participant.
    std::vector<uint8_t> buffer;
    BilinearGroup::Serializer serializer(buffer);
    serializer << crs;
    std::string str(buffer.begin(), buffer.end());

    for (int i = 0; i < participants.participants_size(); i++)
    {
      //The participant that is being sent to and the boostrapper are not included in the list.
      //Since they are not needed
      Stub<bootstrapper::SendParticipants> stub = clients[i].createStub<bootstrapper::SendParticipants>();
      bootstrapper::Participant elementToSkip = participants.participants(i);
      bootstrapper::Participants copy;
      for (int j = 0; j < participants.participants_size(); ++j)
      {
        if (j != i)
        {
          *copy.add_participants() = participants.participants(j);
        }
      }
      copy.set_crs(str);

      stub.send<bootstrapper::Participants, bootstrapper::Response>(
          copy, participants.participants(i).index(),
          [](bootstrapper::SendParticipants::Stub *stub, grpc::ClientContext *context,
             bootstrapper::Participants *request, bootstrapper::Response *response)
          {
            grpc::Status status = stub->SendParticipants(context, *request, response);
            return status;
          });
      // bootstrapper::SendParticipants
    }
    return {clients, 1};
  }
  else
  {
    std::cout << "Bootstrapping error: Server did not finish successfully" << std::endl;
    exit(1);
  }
}

std::tuple<std::vector<Client>, uint8_t> create_bootstrap_client(const std::string &bootstrapp_address,
                                                                 const int &port_base,
                                                                 grpc::SendParticipantsServiceImpl *service,
                                                                 GS::CRS &crs)
{
  //sents a hello message to the bootstrapper with the port the grpc server of the participant listens to
  bootstrapper::Hello hello;
  hello.set_port(port_base);
  Client bootstrapper = Client(bootstrapp_address, 0);
  Stub<bootstrapper::Bootstrap> stub = bootstrapper.createStub<bootstrapper::Bootstrap>();

  bootstrapper::ParticipantIndex index = stub.send<bootstrapper::Hello, bootstrapper::ParticipantIndex>(
      hello, 0,
      [](bootstrapper::Bootstrap::Stub *stub, grpc::ClientContext *context, bootstrapper::Hello *request,
         bootstrapper::ParticipantIndex *response)
      {
        grpc::Status status = stub->RegisterUser(context, *request, response);
        return status;
      });
  //Receives an index from the bootstrapper, which is used for the DKG's and for the MPC's. This is done to have a unique identifier for each participant.
  std::cout << "my received index: " << index.index() << std::endl;
  bootstrapper::Participants participants = service->pop_queue();
  std::string crs_str = participants.crs();
  std::vector<uint8_t> buffer(crs_str.begin(), crs_str.end());
  BilinearGroup::Deserializer deserializer(buffer);
  deserializer >> crs;
  std::vector<Client> clients = create_clients(participants);
  clients.insert(clients.begin(), bootstrapper);
  return {clients, index.index()};
}
} // namespace Networking