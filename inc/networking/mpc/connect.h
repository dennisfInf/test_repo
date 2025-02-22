#ifndef _MPCCLIENT_H_
#define _MPCCLIENT_H_
#include "ExternalIO/Client.hpp"
#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "crypto/bilinear_group/group.h"
#include "crypto/schemes/threshold_el_gamal/protocol.h"
#include "group.h"
#include <string>
#include <vector>
namespace MPC
{
  class MPCClient
  {
  public:
    Client client;
    MPCClient(int client_id, vector<string> &hostnames, int n_parties, int bootstrapper, int port_base)
        : client(hostnames, port_base, client_id - 1)
    {
      setup_sockets(n_parties, bootstrapper);
    };
    void send_share(BilinearGroup::BN &share, int index);
    void bootstrap_send_share(BilinearGroup::BN &share, int index);
    void send_G1_point(TEG::DecryptionShare &point);
    void send_G1_points_with_C(std::vector<TEG::DecryptionShare> &points, std::vector<BilinearGroup::G1> &ciphertexts, int &batch_size);

    void init_field();
    bigint get_prime_number();
    BilinearGroup::BN get_share(int index);
    std::vector<BilinearGroup::BN> get_shares(uint8_t &index, int &batch_size);
    void send_G1_points(std::vector<TEG::DecryptionShare> &points, int &batch_size);

  private:
    void check_if_mpc_finished() { this->client.receive_outputs<gfp>(1); }
    void setup_sockets(int n_parties, int bootstrapper);
    template <class T>
    void one_run(std::vector<T> values)
    {
      // Run the computation
      client.send_private_inputs<T>(values);
    }
  };
}; // namespace MPC
#endif