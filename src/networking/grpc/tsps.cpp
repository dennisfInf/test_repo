#include "networking/grpc/tsps.h"
#include "crypto/schemes/tsps/setup.h"

namespace grpc
{
//This methods here only push the request to the queue, which is popped by the TSPS protocol. Also some checks are done, if enough messages are received
grpc::Status TSPServiceImpl::Send_Commited_Shares(grpc::ServerContext *, const tsps::Commited_Share *request,
                                                  tsps::Response *)
{
  if (this->seen >= max_amount)
  {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Already received enough commited shares");
  }
  // To Do: check if a participant sends more than one message
  {
    std::lock_guard<std::mutex> lock(this->seen_mutex);
    seen++;
    this->commited_share_queue.push(*request);
  }
  return grpc::Status::OK;
}

grpc::Status TSPServiceImpl::Send_Matrix(grpc::ServerContext *, const tsps::Matrix *request, tsps::Response *)
{
  if (this->seen_public_parameters >= tsps::public_parameters_size())
  {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Already received enough matrices");
  }
  {
    std::lock_guard<std::mutex> lock(this->seen_public_parameters_mutex);
    this->seen_public_parameters++;
    this->matrix_queue.push(*request);
  }
  return grpc::Status::OK;
}

grpc::Status TSPServiceImpl::Send_Message(grpc::ServerContext *, const tsps::Message *request, tsps::Response *)
{
  this->message_queue.push(*request);
  return grpc::Status::OK;
}

grpc::Status TSPServiceImpl::Send_PartialSignature(grpc::ServerContext *, const tsps::PartialSignatureProto *request,
                                                   tsps::Response *)
{
  this->partial_signature_queue.push(*request);
  return grpc::Status::OK;
}

grpc::Status TSPServiceImpl::Send_Verification_Key(grpc::ServerContext *, const tsps::Matrix *request, tsps::Response *)
{
  if (this->seen_verify_keys >= max_amount)
  {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Already received enough commited shares");
  }
  // To Do: check if a participant sends more than one message
  {
    std::lock_guard<std::mutex> lock(this->seen_verify_mutex);
    seen_verify_keys++;
    this->verification_key_queue.push(*request);
  }
  return grpc::Status::OK;
}

} // namespace grpc