#pragma once
#include "string"
#include "vector"
#include <cstdint>

namespace Config
{
    struct Parties
    {
        std::string prev;
        std::string next;
    };

    struct Values
    {
        std::vector<std::string> hostnames;
        std::string entries_webserver;
        uint8_t my_index;
        bool BUILD_BOTTOM_LEVEL_AT_STARTUP;
        uint LOG_ADDRESS_SPACE;
        uint NUM_LEVELS;
        uint LOG_AMP_FACTOR;
        uint threads;
    };
    std::string extractPort(const std::string &address);

    Values create_config(int argc, char **argv);
    Parties get_addresses(std::vector<std::string> &hostnames, uint8_t &my_index);

    void add_to_port(std::string &address, int num);

} // namespace Config