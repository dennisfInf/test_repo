#include "config.h"
#include "crypto/bilinear_group/serializer.h"
#include "crypto/bookkeeping_proofs/setup.h"
#include "Math/gfpvar.cpp"
#include "Math/gfpvar.h"
#include "Math/bigint.h"
#include "home_operator/protocol.h"
#include "home_operator/structs.h"
#include "iostream"
#ifdef ENABLE_GDORAM
#include "builder.h"
#endif
#include "networking/bootstrapping.h"
#include "networking/client.h"
#include "networking/mpc/serialization.h"
#include "networking/server.h"
#include "user/protocol.h"
#include "main.h"
#include "user/structs.h"
#include <vector>

/* TO DO'S:s
- Multi scalar mult mit public scalars
- MPC vectorization
- error handling
- get rid of ints
- comment code
- add authentication
- add TLS between nodes
- remove unnecessary includes
- check pp before signing
- impl lfree
- implement periods
- create function to send to all participants
- RISS scheme one error (not handling multiple shares, works for t = n-1)
- use more pointers, instead of copying the values
- remove bootstrap process (unnecessary, because MP-SPDZ requires all ip's for our server setting )
- (MP-SPDZ also has a bootstrapping process, which does not work for our servers)
- REMOVE DUPLICATE CODE BETWEEN GIGADORAM,SEMI-HONEST AND MAL IN INSERT ENTRY
 */

int main(int argc, char **argv)
{
  // Creates a config object from the command line arguments
  Config::Values config = Config::create_config(argc, argv);
  int runs = 1;
  int batch_size = 100;
  // Creates a map of required grpc services
  std::map<std::string, grpc::Service *> services =
      Networking::create_service_map(config.n_parties, config.l, config.k);
  // Starts the grpc server
  std::thread t([&services, &config]()
                { Networking::RunServer(config.port, config.my_address, services); });
  GS::CRS crs_nizk;
  // Runs a bootstrapping process to get the clients and the number of parties. Also gets the crs for the NIZK.
  std::tuple<std::vector<Networking::Client>, uint8_t> clients =
      Networking::run_bootsstrap(config.bootstrap, config.port, config.bootstrap_address, services, crs_nizk);
  // Creates a client to MPC_2 and gets the prime number the MPC is using
  tsps::Protocol *tsps;
  crs_nizk.precompute();
  uint total_runs = static_cast<uint>(runs * batch_size);
#ifdef ENABLE_GDORAM
  bookkeeping::HomeOperatorHonest *ho;
  tsps = new tsps::Protocol(std::get<0>(clients), config.n_parties, config.t, config.k, config.l, std::get<1>(clients), services, crs_nizk, total_runs);
  Config::Parties parties = Config::get_addresses(clients, config.port);
  Config::add_to_port(parties.prev, 3);
  Config::add_to_port(parties.next, 3);
  config.oram_addresses = config.oram_addresses + 9;
  if (config.oram_addresses > 32)
  {
    config.oram_addresses = 32;
  };
  std::cout << "init oram" << std::endl;
  emp::rep_array_unsliced<emp::y_type> *ys = emp::init(std::get<1>(clients), parties.prev, parties.next, false,
                                                       config.oram_addresses, config.num_levels, config.amp_factor, 4);
  std::cout << "init oram finished" << std::endl;

  ho = new bookkeeping::HomeOperatorHonest(config.bootstrap, std::get<0>(clients), config.n_parties, config.t,
                                           std::get<1>(clients), services, config.hostnames_mpc1, config.mpc_port_base, crs_nizk, config.oram_addresses, config.num_levels,
                                           config.amp_factor, ys, tsps);
  start_protocol(ho, config, clients, crs_nizk, runs, batch_size);

#else
  bookkeeping::HomeOperatorBase *ho;
  MPC::MPCClient mpc_client_oram(std::get<1>(clients), config.hostnames_mpc2, config.n_parties, config.bootstrap, config.mpc_port_base + 256);
  bigint prime = mpc_client_oram.get_prime_number();
  // Initializes the field with the prime number.
  gfpvar_<1, 6>::init_field(prime);
  BilinearGroup::BN q = MPC::conv_bigint_to_bn(prime); // Converts the prime number to a RELIC BN
                                                       // Creates a home operator object. This already initializes the TSPS, the ElGamal and the RISS schemes by running a DKG with other operators.
                                                       // Also a connection to MPC1 is established and the BLS keys are generated.
  if (config.malicious)
  {
    tsps = new tsps::ProtocolMal(std::get<0>(clients), config.n_parties, config.t, config.k, config.l, std::get<1>(clients), services, crs_nizk, total_runs);
    tsps::ProtocolMal *derived_tsps = dynamic_cast<tsps::ProtocolMal *>(tsps);
    ho = new bookkeeping::HomeOperatorMal(config.bootstrap, std::get<0>(clients), config.n_parties, config.t,
                                          std::get<1>(clients), services, config.hostnames_mpc1, config.mpc_port_base, crs_nizk, 6, 2,
                                          q, mpc_client_oram, derived_tsps);
  }
  else
  {
    tsps = new tsps::Protocol(std::get<0>(clients), config.n_parties, config.t, config.k, config.l, std::get<1>(clients), services, crs_nizk, total_runs);

    ho = new bookkeeping::HomeOperatorHonest(config.bootstrap, std::get<0>(clients), config.n_parties, config.t,
                                             std::get<1>(clients), services, config.hostnames_mpc1, config.mpc_port_base, crs_nizk, 6, 2,
                                             q, mpc_client_oram, tsps);
  }
  start_protocol(ho, config, clients, crs_nizk, runs, batch_size);
#endif
  delete tsps;
  delete ho;
  return 0;
}
