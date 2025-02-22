#include "networking/server.h"
#include "networking/grpc/bootstrap.h"
#include "networking/grpc/dkg.h"
#include "networking/grpc/el_gamal.h"
#include "networking/grpc/riss.h"
#include "networking/grpc/tsps.h"
#include "networking/server.h"

//Creates a map for all grpc services. This is needed, because internally every grpc service uses a queue to push the received messages to it.
//By the pointer to the service, this queue can is used to pop received messages from it.
//For this, because a map of the parent class 'grpc services' is used, the services have to be casted to the right service
//before being able to access the queue
std::map<std::string, grpc::Service *> Networking::create_service_map(uint8_t &n, uint8_t &l, uint8_t &k)
{
  std::map<std::string, grpc::Service *> services;
  services.insert(std::make_pair("bootstrap", new grpc::BootstrapServiceImpl(n)));
  services.insert(std::make_pair("send_participants", new grpc::SendParticipantsServiceImpl(n)));
  services.insert(std::make_pair("dkg", new grpc::DKGServiceImpl(n)));
  services.insert(std::make_pair("teg", new grpc::TEGServiceImpl()));
  // l +1, k +1 Matrix is used for the Keys
  services.insert(std::make_pair("tsps", new grpc::TSPServiceImpl(n, l + 1, k + 1)));
  services.insert(std::make_pair("riss", new grpc::RISSServiceImpl()));

  return services;
}
