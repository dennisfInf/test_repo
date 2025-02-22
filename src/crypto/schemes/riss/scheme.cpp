#include "crypto/schemes/riss/scheme.h"
#include "crypto/bilinear_group/group.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include "networking/grpc/serialize.h"
#include "protos/riss.grpc.pb.h"
#include <algorithm>

namespace RISS
{

void Protocol::receive_shares(sub_proc &sub_protocol, int &index_in_complements)
{
  int counter = 0;
  int max_received_shares = index_in_complements * (n - 1);
  while (counter < max_received_shares)
  {
    riss::Share share = rissService->share_queue_pop();
    Share newShare = Share{grpc::deserialize_from_string<BilinearGroup::BN>(share.value())[0], share.share_index()};
    sub_protocol.insert_share(share.party_index(), newShare);
    counter++;
  };
}

void Protocol::receive_r_values(sub_proc &sub_protocol)
{
  int counter = 1;
  while (counter < n)
  {
    riss::R r = rissService->r_queue_pop();
    BilinearGroup::BN r_value = grpc::deserialize_from_string<BilinearGroup::BN>(r.value())[0];
    sub_protocol.insert_r_value(r.party_index(), r_value);
    counter++;
  };
}

std::vector<Share> Protocol::receive_shamir_shares()
{
  int counter = 0;
  std::vector<Share> shares;
  while (counter < n - 1)
  {
    riss::ShamirShare share = rissService->shamir_share_queue_pop();
    Share newShare = Share{grpc::deserialize_from_string<BilinearGroup::BN>(share.value())[0], share.party_index()};
    shares.push_back(newShare);
    counter++;
  };
  return shares;
}

void Protocol::send_share(std::vector<int> &party_indices, Share &share, sub_proc &sub_protocol)
{
  riss::Share share_msg;
  share_msg.set_value(grpc::serialize_to_string(share.share));
  share_msg.set_party_index(my_index - 1);
  share_msg.set_share_index(share.index);
  std::vector<std::future<void>> futures;
  for (auto index : party_indices)
  {
    if (index == my_index - 1)
    {
      sub_protocol.insert_share(my_index - 1, share);
      continue;
    }
    else if (index > my_index - 1)
    {
      index--;
    }
    futures.push_back(BilinearGroup::pool.push(
        [this, &share_msg, index](int)
        {
          Networking::Stub<riss::RISS> stub = this->participants[index].createStub<riss::RISS>();
          stub.send<riss::Share, riss::Response>(
              share_msg, index + 1,
              [](riss::RISS::Stub *stub, grpc::ClientContext *context, riss::Share *request, riss::Response *response)
              {
                grpc::Status status = stub->SendShare(context, *request, response);
                return status;
              });
        }));
  }
  for (auto &f : futures)
  {
    f.wait();
  }
  // send share to indices
}

void Protocol::send_shamir_share(BilinearGroup::BN &share)
{
  riss::ShamirShare share_msg;
  share_msg.set_value(grpc::serialize_to_string(share));
  share_msg.set_party_index(my_index - 1);
  std::vector<std::future<void>> futures;
  for (auto &participant : this->participants)
  {
    futures.push_back(BilinearGroup::pool.push(
        [this, &share_msg, &participant](int)
        {
          Networking::Stub<riss::RISS> stub = participant.createStub<riss::RISS>();
          stub.send<riss::ShamirShare, riss::Response>(share_msg, 1,
                                                       [](riss::RISS::Stub *stub, grpc::ClientContext *context,
                                                          riss::ShamirShare *request, riss::Response *response)
                                                       {
                                                         grpc::Status status =
                                                             stub->SendShamirShare(context, *request, response);
                                                         return status;
                                                       });
        }));
  }
  for (auto &f : futures)
  {
    f.wait();
  }
}

void Protocol::send_r(BilinearGroup::BN r)
{
  riss::R r_msg;
  r_msg.set_value(grpc::serialize_to_string(r));
  r_msg.set_party_index(my_index - 1);
  std::vector<std::future<void>> futures;
  for (auto &participant : this->participants)
  {
    futures.push_back(BilinearGroup::pool.push(
        [this, &r_msg, &participant](int)
        {
          Networking::Stub<riss::RISS> stub = participant.createStub<riss::RISS>();
          stub.send<riss::R, riss::Response>(
              r_msg, 1,
              [](riss::RISS::Stub *stub, grpc::ClientContext *context, riss::R *request, riss::Response *response)
              {
                grpc::Status status = stub->SendR(context, *request, response);
                return status;
              });
        }));
  };
  for (auto &f : futures)
  {
    f.wait();
  }
}

void Protocol::send_RISS_Shares(RISSShares &shares,
                                std::vector<std::pair<std::vector<int>, std::vector<int>>> &sets_and_complements,
                                sub_proc &sub_protocol)
{
  std::vector<std::future<void>> futures;

  futures.push_back(BilinearGroup::pool.push([this, &shares](int) { this->send_r(shares.r); }));

  for (int i = 0; i < shares.shares.size(); i++)
  {
    futures.push_back(BilinearGroup::pool.push(
        [this, &share = shares.shares[i], &complement = sets_and_complements[i].second, &sub_protocol](int)
        { this->send_share(complement, share, sub_protocol); }));
  };
  for (auto &f : futures)
  {
    f.wait();
  }
}

void Protocol::input_my_share_into_prf()
{
  my_share.r_p = BilinearGroup::BN::prf(my_share.r_p, prf_counter, l);
  prf_counter++;
  // calculate r_p new and r_q new
}

BilinearGroup::BN Protocol::convert_share(BilinearGroup::BN &fp_share)
{
  // MP-SPDZ returns additive shares
  BilinearGroup::BN result = riss_scheme.calc_share_plus_r(fp_share, my_share.r_p);
  std::future<void> fut = BilinearGroup::pool.push([this, &result](int) { this->send_shamir_share(result); });
  std::vector<Share> shares = receive_shamir_shares();
  shares.push_back(Share{result, my_index - 1});
  fut.wait();
  BilinearGroup::BN fp_val_plus_r = riss_scheme.open_value(shares);
  return riss_scheme.convert_opened_value(fp_val_plus_r, my_share.r_q);
}

void Protocol::print_opened_value(BilinearGroup::BN &share){
  std::future<void> fut = BilinearGroup::pool.push([this, &share](int) { this->send_shamir_share(share); });
  std::vector<Share> shares = receive_shamir_shares();
  shares.push_back(Share{share, my_index - 1});
  fut.wait();
  BilinearGroup::BN opened_value = riss_scheme.open_value(shares);
  opened_value.print();
}

void Protocol::print_opened_value_q(BilinearGroup::BN &share){
  std::future<void> fut = BilinearGroup::pool.push([this, &share](int) { this->send_shamir_share(share); });
  std::vector<Share> shares = receive_shamir_shares();
  shares.push_back(Share{share, my_index - 1});
  fut.wait();
    BilinearGroup::BN result = BilinearGroup::BN(0);
  for (auto &share : shares)
  {
    BilinearGroup::BN::add_without_mod(result, result,share.share);
  }
  result %= q;
  result.print();
}



} // namespace RISS