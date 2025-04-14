
#pragma once
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

namespace Networking
{
  template <typename T>
  class Stub
  {
  public:
    Stub(std::shared_ptr<grpc::Channel> channel) : stub_(T::NewStub(channel)) {}
    template <typename U, typename V, typename Func>
    V send(U &request, uint32_t participant_index, Func func)
    {
      V response;
      grpc::Status status;
      uint8_t counter = 0;
      do
      {
        grpc::ClientContext context;
        std::chrono::system_clock::time_point deadline = std::chrono::system_clock::now() + std::chrono::seconds(10);
        context.set_deadline(deadline);
        status = func(stub_.get(), &context, &request, &response);
        if (!status.ok())
        {
          std::cout << "Error communicating with participant with index " << participant_index << ": "
                    << status.error_code() << ": " << status.error_message() << std::endl;
          std::cout << "Retrying in a second..." << std::endl;
          sleep(1);
          counter++;
        }
      } while (!status.ok() && counter < 15);
      return response;
    }

  private:
    std::unique_ptr<typename T::Stub> stub_;
  };

  class Client
  {
  public:
    Client() = default;
    ~Client() = default;
    Client(std::string address, int index)
        : index(index), address(address), channel(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()))
    {
    }
    std::string get_address()
    {
      return address;
    };
    template <typename T>
    Stub<T> createStub() { return Stub<T>(channel); }

  private:
    int index;
    std::string address;

    std::shared_ptr<grpc::Channel> channel;
  };
} // namespace Networking