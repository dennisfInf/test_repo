#pragma once
#include "string"
#include "vector"
#include <cstdint>
#include "crypto/bilinear_group/group.h"

namespace Config
{
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
    int oram_addresses;
  };

  Values create_config(int argc, char **argv);

} // namespace Config