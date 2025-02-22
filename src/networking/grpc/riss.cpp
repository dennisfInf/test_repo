#include "networking/grpc/riss.h"

namespace grpc
{
//This methods here only push the request to the queue, which is popped by the RISS protocol
grpc::Status RISSServiceImpl::SendShare(grpc::ServerContext *, const riss::Share *request, riss::Response *)

{
  this->share_queue.push(*request);
  return grpc::Status::OK;
}

grpc::Status RISSServiceImpl::SendR(grpc::ServerContext *, const riss::R *request, riss::Response *)
{
  this->r_queue.push(*request);
  return grpc::Status::OK;
}

grpc::Status RISSServiceImpl::SendShamirShare(grpc::ServerContext *, const riss::ShamirShare *request, riss::Response *)
{
  this->shamir_share_queue.push(*request);
  return grpc::Status::OK;
}
} // namespace grpc