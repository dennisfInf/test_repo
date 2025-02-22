#ifndef _SHARE_H_
#define _SHARE_H_
#include "crypto/schemes/secret_sharing/commitments.h"
#include "group.h"
#include "networking/grpc/serialize.h"
#include "protos/threshold_el_gamal.grpc.pb.h"

namespace Participants
{

class Share
{
public:
  Share(){};
  template <typename T> Share(const T &share_proto)
  {
    this->share = this->deserialize_share(share_proto);
    this->receiver_index = share_proto.receiver_index();
  }
  Share(BilinearGroup::BN share, uint8_t receiver_index) : share(share), receiver_index(receiver_index){};
  bool verify(const Commitments::DKG__Commitment &commitment, const uint8_t &my_index);
  BilinearGroup::BN operator+(const BilinearGroup::BN &x) const;
  template <typename T> T serialize_to_proto() const
  {
    T share;
    share.set_share(grpc::serialize_to_string(this->share));
    share.set_receiver_index(this->receiver_index);
    return share;
  }

private:
  template <typename T> BilinearGroup::BN deserialize_share(const T &share_proto)
  {
    std::string share_as_string = share_proto.share();
    return grpc::deserialize_from_string<BilinearGroup::BN>(share_as_string)[0];
  }

  BilinearGroup::BN share;
  int receiver_index;
};
struct Com_Shares
{
  Commitments::DKG__Commitment commitment;
  Share share;
};

template <typename T>
Com_Shares handleCommittedShare(T &queue_value, const std::string &context, const uint8_t &my_index)
{
  // could perform both verification in parallel
  Commitments::DKG_Proposed_Commitments proposed_coms(queue_value.commitment());
  Com_Shares commited_shares;
  std::optional<Commitments::DKG__Commitment> dkg_com = proposed_coms.verify(context);
  if (dkg_com.has_value())
  {

    commited_shares.commitment = dkg_com.value();
    Share share = Share(queue_value.share());

    if (share.verify(commited_shares.commitment, my_index))
    {
      commited_shares.share = share;
    }
    else
    {
      std::cout << "invalid share" << std::endl;
      exit(1);
    }
    return commited_shares;
  }
  else
  {
    std::cout << "commitment with index is invalid" << std::endl;
    exit(1);
  }
}

}; // namespace Participants
#endif