#include "networking/grpc/el_gamal.h"

namespace grpc
{
//Only pushes the request to the queue, which is poped by the el_gamal protocol
grpc::Status TEGServiceImpl::InitDecryption(grpc::ServerContext *, const el_gamal::Ciphertext *request,
                                            el_gamal::Response *)
{
  this->ciphertext_queue.push(*request);
  return grpc::Status::OK;
}
} // namespace grpc