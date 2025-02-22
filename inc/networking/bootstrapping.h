#include "crypto/proofs/prelude.hpp"
#include "networking/client.h"
#include "networking/grpc/bootstrap.h"
#include <string>
namespace Networking
{

std::tuple<std::vector<Client>, uint8_t> run_bootsstrap(const bool &bootstrapper, const int &port_base,
                                                        const std::string bootstrap_address,
                                                        std::map<std::string, grpc::Service *> &services,
                                                        GS::CRS &crs);

std::tuple<std::vector<Client>, uint8_t> create_bootstrapper(grpc::BootstrapServiceImpl *service,GS::CRS &crs);

std::tuple<std::vector<Client>, uint8_t> create_bootstrap_client(const std::string &bootstrapp_address,
                                                                 const int &port_base,
                                                                 grpc::SendParticipantsServiceImpl *service,GS::CRS &crs);
} // namespace Networking