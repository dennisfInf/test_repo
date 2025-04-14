#include "entries.h"
namespace HTTP
{
    Json::Value::Int last_number = 0;

    size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *output)
    {
        size_t totalSize = size * nmemb;
        output->append((char *)contents, totalSize);
        return totalSize;
    }

    void curl_website(std::string &address, std::vector<uint32_t> &nums, std::vector<uint32_t> &nums_conv)
    {
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            std::cerr << "Failed to initialize curl" << std::endl;
        }
        else
        {

            std::string response;
            std::cout << "address in curl: " << address << std::endl;
            std::string full_url = "https://" + address + "/entries";
            std::cout << "address in curl: " << full_url << std::endl;

            curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            }
            else
            {
                std::cout << "Response: " << response << std::endl;
                Json::CharReaderBuilder reader;
                Json::Value root;
                std::string errors;

                std::istringstream s(response);
                if (Json::parseFromStream(reader, s, &root, &errors))
                {
                    Json::Value lastItem = root[root.size() - 1];
                    Json::Value::Int number = lastItem["nummer"].asInt();
                    std::cout << "last number: " << last_number << " number: " << number << std::endl;
                    if (last_number < number)
                    {

                        Json::Value::Int difference = number - last_number;
                        last_number = number;

                        if (difference > 0)
                        {
                            if (difference >= 100)
                            {
                                difference = 100;
                            }
                            for (int i = 1; i <= difference; i++)
                            {
                                Json::Value item = root[root.size() - i];
                                Json::String name = item["name"].asString();
                                if (name == "Alice")
                                {
                                    nums.push_back(1);
                                    nums_conv.push_back(0);
                                }
                                else if (name == "Bob")
                                {
                                    nums.push_back(302);
                                    nums_conv.push_back(1);
                                }
                                else if (name == "Charlie")
                                {
                                    nums.push_back(603);
                                    nums_conv.push_back(2);
                                }
                                else if (name == "David")
                                {
                                    nums.push_back(904);
                                    nums_conv.push_back(3);
                                }
                                else if (name == "Eve")
                                {
                                    nums.push_back(1205);
                                    nums_conv.push_back(4);
                                }
                                else if (name == "Valerie")
                                {
                                    nums.push_back(1506);
                                    nums_conv.push_back(5);
                                }
                            }
                        }
                    }
                }
                else
                {
                    std::cerr << "Failed to parse JSON: " << errors << std::endl;
                }

                curl_easy_cleanup(curl);
            }
        }
    }
}