#include "networking/grpc/dkg.h"

namespace grpc
{

  // Is called then other operators are sending commited shares in the DKG protocol. Checks if already enough shares a received.
  grpc::Status DKGServiceImpl::Send_Commited_Shares(grpc::ServerContext *, const el_gamal::Commited_Share *request,
                                                    el_gamal::Response *)
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

  grpc::Status DKGServiceImpl::Send_Participant_PK(grpc::ServerContext *, const el_gamal::Participant_Public_Key *request,
                                                   el_gamal::Response *)
  {
    if (this->seen_pk >= max_amount)
    {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Already received enough commited shares");
    }
    // To Do: check if a participant sends more than one message
    {
      std::lock_guard<std::mutex> lock(this->seen_pk_mutex);
      seen_pk++;
      this->participant_pk_queue.push(*request);
    }
    return grpc::Status::OK;
  }

} // namespace grpc