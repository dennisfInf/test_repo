#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/bls_sig/scheme.h"
#include "crypto/schemes/riss/scheme.h"
#include "crypto/schemes/threshold_el_gamal/participant.h"
#include "crypto/schemes/threshold_el_gamal/protocol.h"
#include "crypto/schemes/tsps/protocol.h"
#include "home_operator/structs.h"
#include "networking/client.h"
#include "networking/mpc/connect.h"
#include "networking/thread_channel/safe_queue.h"
#include "user/structs.h"
#include <vector>
namespace bookkeeping
{
  struct PublicKeys
  {
    BilinearGroup::G1 ek_all;
    BilinearGroup::G1 vk_ho;
    BilinearGroup::Matrix<BilinearGroup::G2> vk_all;
  };

  struct ThresholdSignature
  {
    tsps::SignatureM threshold_signature;
    BilinearGroup::FP address;
  };
  class HomeOperator
  {
  public:
    // hard-coded context should be changed in production
    HomeOperator(bool bootstrapper, std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t,
                 const uint8_t &my_index,
                 std::map<std::string, grpc::Service *> &services, std::vector<std::string> &hostnames, int mpc_port_base,
                 GS::CRS crs_nizk, const uint8_t riss_l, const uint8_t riss_k, BilinearGroup::BN riss_mod_q, MPC::MPCClient &mpc_client_oram)
        : el_gamal(participants, n, my_index, "context"), mpc_client(my_index, hostnames, n, bootstrapper, mpc_port_base), t(t), current_addr(1),
          crs_nizk(crs_nizk), riss(my_index, n - 1, n, riss_l, riss_k, participants, riss_mod_q, services),
          ho_index(my_index), mpc_client2(&mpc_client_oram)
    {
      mpc_client.init_field();
      grpc::DKGServiceImpl *dkgService = Networking::cast_service<grpc::DKGServiceImpl>(services, "dkg");
      tegService = Networking::cast_service<grpc::TEGServiceImpl>(services, "teg");

      el_gamal.run_dkg(dkgService, n, t);
      bls_sig.generate_keys();
    }
    virtual PublicKeys get_public_keys() { return PublicKeys{}; };
    PublicKeys get_public_keys(tsps::Protocol *tsps) { return {el_gamal.get_public_key(), bls_sig.get_public_key(), tsps->get_public_key()}; }
    tsps::PublicParameters get_public_parameters(tsps::Protocol *tsps) { return tsps->get_public_parameters(); }
    virtual tsps::PublicParameters get_public_parameters() { return tsps::PublicParameters{}; };

    bool prove_entry(proof_prove_entry &ppe, tsps::Protocol *tsps);
    virtual bool prove_entry([[maybe_unused]] proof_prove_entry &ppe) { return false; };
    BenchmarkInsertEntry calc_decryption_shares(BilinearGroup::BN &period, BilinearGroup::BN &msg, int &runs, int &batch_size, tsps::Protocol *tsps);
    virtual BenchmarkInsertEntry calc_decryption_shares([[maybe_unused]] BilinearGroup::BN &period, [[maybe_unused]] BilinearGroup::BN &msg, [[maybe_unused]] int &runs, [[maybe_unused]] int &batch_size) { return BenchmarkInsertEntry{}; };

    ThresholdSignature register_user(bookkeeping::proof_sk_u &proof_sk_u, tsps::Protocol *tsps);
    virtual ThresholdSignature register_user([[maybe_unused]] bookkeeping::proof_sk_u &proof_sk_u) { return ThresholdSignature{}; };

    BLS::Signature create_entry(proof_create_entry_user &p_ce, BilinearGroup::BN &msg, BilinearGroup::BN &period, tsps::Protocol *tsps);
    virtual BLS::Signature create_entry([[maybe_unused]] proof_create_entry_user &p_ce, [[maybe_unused]] BilinearGroup::BN &msg, [[maybe_unused]] BilinearGroup::BN &period) { return BLS::Signature{}; };

  protected:
    SafeQueue<PendingEntry> l_pending;
    TEG::Protocol el_gamal;
    void input_to_mpcs(std::chrono::_V2::system_clock::time_point &start_mpc1, bool bootstrap, double &mpc_time1, double &mpc_time2, std::future<void> &oram_ready_fut, SafeQueue<bool> &mpc_ready_queue, int &batch_size);
    MPC::MPCClient mpc_client;
    uint8_t t;
    grpc::TEGServiceImpl *tegService;

  private:
    BilinearGroup::FP current_addr;
    BilinearGroup::FP retrieve_current_addr() { return current_addr; };
    bool verify_create_entry_proof(proof_create_entry_user &p_ce, std::vector<uint8_t> &h, tsps::Protocol *tsps);
    void increment_addr() { current_addr.increment(); };
    std::vector<LKey> l_keys;
    std::mutex l_lkeys_mtx;
    BLS::Signatures bls_sig;
    void add_lkeys_entry(LKey l_key)
    {
      std::lock_guard<std::mutex> lock(this->l_lkeys_mtx);
      l_keys.push_back(l_key);
    };
    std::mutex current_addr_mtx;
    GS::CRS crs_nizk;
    RISS::Protocol riss;
    uint8_t ho_index;
    MPC::MPCClient *mpc_client2;
    BilinearGroup::BN mod_q;
  };

  class HomeOperatorBase : public HomeOperator
  {
  public:
    // hard-coded context should be changed in production
    HomeOperatorBase(bool bootstrapper, std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t,
                     const uint8_t &my_index,
                     std::map<std::string, grpc::Service *> &services, std::vector<std::string> &hostnames, int mpc_port_base,
                     GS::CRS crs_nizk, const uint8_t riss_l, const uint8_t riss_k, BilinearGroup::BN riss_mod_q, MPC::MPCClient &mpc_client_oram, tsps::Protocol *tsps)
        : HomeOperator(bootstrapper, participants, n, t, my_index, services, hostnames, mpc_port_base, crs_nizk, riss_l, riss_k, riss_mod_q, mpc_client_oram), tsps(tsps)
    {
      tsps->init(bootstrapper);
    }

    PublicKeys get_public_keys() override
    {
      return this->HomeOperator::get_public_keys(tsps);
    }
    tsps::PublicParameters get_public_parameters() override
    {
      return this->HomeOperator::get_public_parameters(tsps);
    }
    bool prove_entry(proof_prove_entry &ppe) override
    {
      return this->HomeOperator::prove_entry(ppe, tsps);
    }

    BLS::Signature create_entry(proof_create_entry_user &p_ce, BilinearGroup::BN &msg, BilinearGroup::BN &period) override
    {
      return this->HomeOperator::create_entry(p_ce, msg, period, tsps);
    }
    BenchmarkInsertEntry calc_decryption_shares(BilinearGroup::BN &period, BilinearGroup::BN &msg, int &runs, int &batch_size) override
    {
      return this->HomeOperator::calc_decryption_shares(period, msg, runs, batch_size, tsps);
    }
    ThresholdSignature register_user(bookkeeping::proof_sk_u &proof_sk_u) override
    {
      return this->HomeOperator::register_user(proof_sk_u, tsps);
    }
    virtual BenchmarkInsertEntry insert_entry([[maybe_unused]] int &runs, [[maybe_unused]] int &batch_size) { return BenchmarkInsertEntry{}; }

  private:
    tsps::Protocol *tsps;
  };
  class HomeOperatorHonest : public HomeOperatorBase
  {
  public:
    // hard-coded context should be changed in production
    HomeOperatorHonest(bool bootstrapper, std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t,
                       const uint8_t &my_index,
                       std::map<std::string, grpc::Service *> &services, std::vector<std::string> &hostnames, int mpc_port_base,
                       GS::CRS crs_nizk, const uint8_t riss_l, const uint8_t riss_k, BilinearGroup::BN riss_mod_q, MPC::MPCClient &mpc_client_oram, tsps::Protocol *tsps)
        : HomeOperatorBase(bootstrapper, participants, n, t, my_index, services, hostnames, mpc_port_base, crs_nizk, riss_l, riss_k, riss_mod_q, mpc_client_oram, tsps)
    {
    }
    BenchmarkInsertEntry insert_entry(int &runs, int &batch_size) override;
  };

  class HomeOperatorMal : public HomeOperatorBase
  {
  public:
    // hard-coded context should be changed in production
    HomeOperatorMal(bool bootstrapper, std::vector<Networking::Client> &participants, const uint8_t &n, const uint8_t &t,
                    const uint8_t &my_index,
                    std::map<std::string, grpc::Service *> &services, std::vector<std::string> &hostnames, int mpc_port_base,
                    GS::CRS crs_nizk, const uint8_t riss_l, const uint8_t riss_k, BilinearGroup::BN riss_mod_q, MPC::MPCClient &mpc_client_oram, tsps::ProtocolMal *tsps)
        : HomeOperatorBase(bootstrapper, participants, n, t, my_index, services, hostnames, mpc_port_base, crs_nizk, riss_l, riss_k, riss_mod_q, mpc_client_oram, tsps)
    {
    }
    BenchmarkInsertEntry insert_entry(int &runs, int &batch_size) override;
  };
} // namespace bookkeeping