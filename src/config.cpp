#include "config.h"
#include "group.h"
#include "iostream"
#include <gmp.h>
#include <string>
#include <vector>
namespace Config
{

  // Convert a string containing a one or zero to a boolean value
  bool stringToBool(const std::string &s)
  {
    if (s == "1")
    {
      return true;
    }
    else if (s == "0")
    {
      return false;
    }
    else
    {
      // Handle error: the string does not represent a boolean value
      throw std::invalid_argument("Invalid boolean string");
    }
  }

  // Convert a string containing a decimal number to a vector of bytes
  std::vector<uint8_t> decimalStringToBytes(const std::string &str)
  {
    mpz_t num;
    mpz_init_set_str(num, str.c_str(), 10); // Initialize gmp num with the decimal number in str

    size_t count = (mpz_sizeinbase(num, 2) + CHAR_BIT - 1) / CHAR_BIT; // Calculate the required buffer size
    uint8_t *buffer = new uint8_t[count];                              // Allocate the buffer

    mpz_export(buffer, NULL, -1, 1, 1, 0, num); // Export num to buffer in big endian format

    std::vector<uint8_t> bytes(buffer, buffer + count); // Convert the buffer to a vector

    mpz_clear(num);  // Clear num
    delete[] buffer; // Delete the buffer

    return bytes;
  }

  // reads the hostnames from a file
  std::vector<std::string> readHostnames(const std::string &filename)
  {
    std::ifstream file(filename);
    std::vector<std::string> hostnames;
    std::string line;

    while (std::getline(file, line))
    {
      hostnames.push_back(line);
    }

    return hostnames;
  }

  // Creates an object of the Config::Values struct from the command line arguments
  Config::Values create_config(int argc, char **argv)
  {
    std::cout << "Relic configuration:\n";
    BilinearGroup::config();
    BilinearGroup::G1 x1 = BilinearGroup::G1::rand();
    x1.print_coordinates();
    BilinearGroup::G1 x2 = x1 + x1;
    x2.norm();
    x2.print_coordinates();
    std::cout << "\n";

    // Reads the hostnames of these files
    std::vector<std::string> hostnames_mpc1 = readHostnames("hostnames_mpc1.txt");
    std::vector<std::string> hostnames_mpc2 = readHostnames("hostnames_mpc2.txt");

    // Prints the usage of the program if the number of arguments is less than 5
    if (argc < 9)
    {
      std::cout << "Usage is ./ippa <number of mpc parties (n)> "
                << "<bootstrapper (0 false, 1 true)> <threshold> <grpc_port> <mpc_port_base>"
                   "<bootstrapper ip:port> <malicious (0 false, 1 true)> <optional #oram addresses (GigaDORAM is used if specified)>"
                << std::endl;
      exit(0);
    }
    // only takes the first n hostnames in the file, since more are not required
    uint8_t n_parties = static_cast<uint8_t>(std::stoi(argv[1]));
    hostnames_mpc1.resize(n_parties);
    hostnames_mpc2.resize(n_parties);
    uint8_t t = static_cast<uint8_t>(std::stoi(argv[3]));
    // Checks if the threshold is greater or equal to the number of parties
    if (t >= n_parties)
    {
      std::cerr << "Threshold t cannot be greater or equal than/to the number of parties n";
      exit(1);
    }
    int port_base = atoi(argv[5]);

    uint8_t k = 1;
    uint8_t l = k + 1;
    int oram_addresses = 0;
    bool malicious = stringToBool(argv[8]);
    if (argc == 10)
    {
      oram_addresses = atoi(argv[9]);
    }
    return Config::Values{n_parties,
                          stringToBool(argv[2]),
                          t,
                          atoi(argv[4]),
                          port_base,
                          argv[7],
                          hostnames_mpc1,
                          hostnames_mpc2,
                          argv[6],
                          l,
                          k,
                          malicious,
                          oram_addresses};
  }

} // namespace Config