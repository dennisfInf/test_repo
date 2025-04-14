
#include "config.h"
#include "iostream"
#include <string>
#include <fstream>
#include "utils_d.h"
#include "globals.h"
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
        // Reads the hostnames of these files
        std::vector<std::string> hostnames = readHostnames("hostnames.txt");
        // Prints the usage of the program if the number of arguments is less than 5
        if (argc < 6)
        {
            std::cout << "Usage is ./doram <my index>  "
                      << "<ORAM: BUILD_BOTTOM_LEVEL_AT_STARTUP (0,1)> <ORAM: LOG_ADDRESS_SPACE> <ORAM: NUM_LEVELS> "
                      << "<ORAM: LOG_AMP_FACTOR>"
                      << std::endl;
            exit(0);
        }
        std::cout << "reading hostnames " << std::endl;
        std::cout << "hostnames.size() " << hostnames.size() << std::endl;
        std::string entries_web;
        if (hostnames.size() < 4 || hostnames[0] == "")
        {
            std::cout << "no hostnames provided in the config file under hostnames.txt .." << std::endl;
            std::cout << "create a hostnames.txt in the root folder with ip:port in each line for each server.." << std::endl;
            std::cout << "there should be 4 lines in total, with the fourth being the webserver.." << std::endl;
            std::cout << "defaulting to localhost.." << std::endl;
            hostnames.resize(3);
            for (int i = 0; i < 3; i++)
            {
                hostnames[i] = "127.0.0.1:808" + std::to_string(i);
            }
            std::cout << "webserver ip: " << emp::webserver_address << std::endl;
            std::cout << "webserver port: " << emp::webserver_port << std::endl;
            entries_web = "127.0.0.1:3000";
        }
        else
        {
            uint temp_port = emp::webserver_port;
            emp::parse_host_and_port(hostnames[3], emp::webserver_address, temp_port);
            emp::webserver_port = temp_port;
            entries_web = hostnames[4];
            std::cout
                << "webserver ip: " << emp::webserver_address << std::endl;
            std::cout << "webserver port: " << emp::webserver_port << std::endl;
            hostnames.resize(3);
        }

        // Checks if the threshold is greater or equal to the number of parties
        uint8_t my_index = std::stoi(argv[1]);

        uint LOG_ADDRESS_SPACE = std::stoi(argv[2]);
        LOG_ADDRESS_SPACE += 9;

        // 4 Values per entry and 100 entries per user. to hold all entries 2^9=512 is needed, this is why the +9 is additonally added.
        // The id of a user is in {0,..,2^LogAddrSpace}
        // and every user has a address space from id*4*100 to (id+1)*4*100}
        uint NUM_LEVELS = std::stoi(argv[3]);
        uint LOG_AMP_FACTOR = std::stoi(argv[4]);
        uint threads = std::stoi(argv[6]);

        return Config::Values{
            hostnames,
            entries_web,
            my_index,
            stringToBool(argv[5]),
            LOG_ADDRESS_SPACE,
            NUM_LEVELS,
            LOG_AMP_FACTOR,
            threads};
    }

    Parties get_addresses(std::vector<std::string> &hostnames, uint8_t &my_index)
    {
        if (my_index == 1)
        {

            std::string port = extractPort(hostnames[0]);
            std::string receive_port = port;
            add_to_port(receive_port, 3);

            // hier muss der bootstrapper seine eigenen ports zurückliefern
            return {":" + receive_port, ":" + port};
        }
        else if (my_index == 2)
        {
            return {hostnames[0], ":" + extractPort(hostnames[1])};
        }
        else
        {
            std::string next = hostnames[0];
            add_to_port(next, 3);
            return {hostnames[1], next};
        }
    };

    std::string extractPort(const std::string &address)
    {
        size_t pos = address.find(':');
        if (pos == std::string::npos)
        {
            throw std::invalid_argument("Invalid address format");
        }
        return address.substr(pos + 1);
    }

    void add_to_port(std::string &address, int num)
    {
        address.back() = address.back() + num;
    }

} // namespace Config