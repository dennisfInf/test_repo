#pragma once
#include <iostream>
#include <curl/curl.h>
#include <json/json.h>

namespace HTTP
{
    extern Json::Value::Int last_number;
    size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *output);
    void curl_website(std::string &address, std::vector<uint32_t> &num, std::vector<uint32_t> &num_conv);
}