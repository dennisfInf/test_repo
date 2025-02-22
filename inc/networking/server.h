#pragma once
#include <grpcpp/server_builder.h>
#include <sstream>
#include <string>

namespace Networking
{
std::map<std::string, grpc::Service *> create_service_map(uint8_t &n, uint8_t &l, uint8_t &k);

template <typename T> T *cast_service(std::map<std::string, grpc::Service *> &services, std::string service_name)
{
  T *service = dynamic_cast<T *>(services[service_name]);
  if (service == nullptr)
  {
    std::cerr << "Invalid service type for " << service_name << std::endl;
    exit(1);
  }
  return service;
}

// blocks thread, call only from a new thread
template <typename T>
void RunServer(const int &port_base, const std::string &hostname, std::map<std::string, T *> &services)
{
  std::stringstream ss;
  ss << hostname << ":" << (port_base);
  std::string server_address = ss.str();
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  for (auto &service : services)
  {
    builder.RegisterService(service.second);
  }
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;
  server->Wait();
}

} // namespace Networking