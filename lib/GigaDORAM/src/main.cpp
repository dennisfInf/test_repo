
#include "config.h"
#include "builder.h"
#include "doram_array.h"
#include "sh_riro_garble.h"
#include "rep_array_unsliced.h"
#include "oram.h"
#include "entries.h"

void fetchEntries(int)
{
}
int main(int argc, char **argv)
{ // Creates a config object from the command line arguments
    Config::Values config = Config::create_config(argc, argv);
    std::cout << "config created" << std::endl;
    // Creates a map of required grpc services
    Config::Parties parties = Config::get_addresses(config.hostnames, config.my_index);
    Config::add_to_port(parties.prev, 3);
    Config::add_to_port(parties.next, 3);
    std::cout << parties.prev << std::endl;
    std::cout << parties.next << std::endl;

    config.LOG_ADDRESS_SPACE = config.LOG_ADDRESS_SPACE;
    std::cout << "init oram" << std::endl;
    emp::rep_array_unsliced<emp::y_type> *ys = emp::init(config.my_index, parties.prev, parties.next, config.BUILD_BOTTOM_LEVEL_AT_STARTUP,
                                                         config.LOG_ADDRESS_SPACE, config.NUM_LEVELS, config.LOG_AMP_FACTOR, config.threads);

    std::cout << "init oram finished" << std::endl;
    emp::DORAM doram(config.LOG_ADDRESS_SPACE, ys, config.NUM_LEVELS, config.LOG_AMP_FACTOR);
    uint length = 0;
    for (int i = 0; i < config.NUM_LEVELS; i++)
    {
        length += doram.total_num_els_and_dummies(i);
    }
    std::cout << "total number of els + dummies " << length << std::endl;
    emp::elems_length = length;
    std::string bootstrap_addr;
    if (emp::party != 3)
    {
        std::string host;
        uint port;
        emp::parse_host_and_port(config.hostnames[0], bootstrap_addr, port);
    }
    std::cout << "setting up oram.." << std::endl;
    DORAM::setup_oram(doram);
    std::cout << "finished setting up oram.." << std::endl;
    std::vector<unsigned long> y_queries{1003, 1003, 1003};
    while (true)
    {
        std::vector<emp::x_type> nums;
        std::vector<emp::x_type> nums_conv;

        HTTP::curl_website(config.entries_webserver, nums, nums_conv);
        for (int i = 0; i < nums.size(); i++)
        {
            emp::x_type num = nums[i];

            if (emp::party == 1)
            {
                std::ostringstream oss;

                oss << "2" << "," << nums_conv[i] << "," << 32;
                std::cout << "party 1 " << oss.str() << std::endl;
                emp::send_data(oss.str());
            }
            DORAM::Query query = DORAM::read_pointer_from_oram(doram, num);
            DORAM::insert_message_in_oram(doram, query.y_value, query.x_value, y_queries, bootstrap_addr);
        }
        std::this_thread::sleep_for(std::chrono::seconds(17)); // Wait 1 second
    }

    sleep(2820130816);
    return 0;
}
