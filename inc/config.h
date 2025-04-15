#pragma once
#include "string"
#include "vector"
#include <cstdint>
#include "crypto/bilinear_group/group.h"
#include "networking/client.h"

namespace Config
{
  struct Parties
  {
    std::string prev;
    std::string next;
  };

  struct Values
  {
    uint8_t n_parties;
    bool bootstrap;
    uint8_t t;
    int port;
    int mpc_port_base;
    std::string bootstrap_address;
    std::vector<std::string> hostnames_mpc1;
    std::vector<std::string> hostnames_mpc2;
    std::string my_address;
    uint8_t l;
    uint8_t k;
    bool malicious;
    int batch_size;
    int oram_addresses;
    int num_levels;
    int amp_factor;
  };

  Values create_config(int argc, char **argv);

  Parties get_addresses(std::tuple<std::vector<Networking::Client>, uint8_t> &clients_tup, int &port);

  void add_to_port(std::string &address, int num);
} // namespace Config