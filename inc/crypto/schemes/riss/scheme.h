#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/schemes/riss/riss.h"
#include "crypto/schemes/riss/sub_protocol.h"
#include "networking/client.h"
#include "networking/grpc/riss.h"
#include "networking/server.h"
#include <list>
#include <vector>

namespace RISS
{

class Protocol
{
public:
  Protocol(uint8_t my_index, uint8_t t, uint8_t n, uint8_t l, uint8_t k, std::vector<Networking::Client> &participants,
           BilinearGroup::BN q, std::map<std::string, grpc::Service *> &services)
      : my_index(my_index), t(t), n(n), l(l), k(k), participants(participants), riss_scheme(my_index, t, n, l, k, q)
  {
    rissService = Networking::cast_service<grpc::RISSServiceImpl>(services, "riss");
    std::vector<std::future<void>> futures;
    this->q = q;
    int index_in_complements = riss_scheme.calc_sets_and_complements();
    riss_scheme.setup();
    RISSInteger riss_shares = riss_scheme.get_secret_ras_r_value();
    std::vector<std::pair<std::vector<int>, std::vector<int>>> sets_and_complements =
        riss_scheme.get_sets_and_complements();
    sub_proc sub_protocol(n, sets_and_complements[0].second.size(), riss_scheme.get_y_values_p(),
                          riss_scheme.get_y_values_q(), q);
    futures.push_back(BilinearGroup::pool.push(
        [this, &riss_shares, &sets_and_complements, &sub_protocol](int)
        { this->send_RISS_Shares(riss_shares.riss_shares, sets_and_complements, sub_protocol); }));
    sub_protocol.insert_r_value(my_index - 1, riss_shares.riss_shares.r);

    futures.push_back(BilinearGroup::pool.push([this, &sub_protocol, &index_in_complements](int)
                                               { receive_shares(sub_protocol, index_in_complements); }));
    futures.push_back(BilinearGroup::pool.push([this, &sub_protocol](int) { receive_r_values(sub_protocol); }));
    for (auto &f : futures)
    {
      f.wait();
    }
    my_share = sub_protocol.finalize_sub_proc();
  };
  BilinearGroup::BN convert_share(BilinearGroup::BN &fp_share);
  void input_my_share_into_prf();

private:
  void print_opened_value_q(BilinearGroup::BN &share);
  void print_opened_value(BilinearGroup::BN &share);
  BilinearGroup::BN q;

  grpc::RISSServiceImpl *rissService;
  void send_RISS_Shares(RISSShares &ras_r_value,
                        std::vector<std::pair<std::vector<int>, std::vector<int>>> &sets_and_complements,
                        sub_proc &proc);
  void send_share(std::vector<int> &party_indices, Share &share, sub_proc &proc);
  void send_r(BilinearGroup::BN r);
  void send_shamir_share(BilinearGroup::BN &share);
  void receive_shares(sub_proc &proc, int &index_in_complements);
  void receive_r_values(sub_proc &proc);
  std::vector<Share> receive_shamir_shares();
  int prf_counter;
  std::mutex shares_mutex;
  std::mutex r_values_mutex;
  r_shares my_share;
  uint8_t my_index;
  uint8_t t;
  uint8_t n;
  uint8_t l;
  uint8_t k;
  std::vector<Networking::Client> &participants;
  Scheme riss_scheme;
};
} // namespace RISS