#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "home_operator/protocol.h"
#include "user/protocol.h"
#include <chrono>

namespace bookkeeping
{
  // The following code is a bit complex. My thought was to only precompute the output of MPC1 on demand.
  // Since MPC1 and MPC2 are running on the same node, MPC1 would otherwise use some resources.


  BenchmarkInsertEntry HomeOperatorHonest::insert_entry(int &runs, int &batch_size)
  {
    SafeQueue<bool> mpc_ready_queue;
    mpc_ready_queue.push(true);

    std::future<void> oram_ready_fut = BilinearGroup::pool.push([](int) {});

    bigint::init_thread();
    double insert_entry_time = 0;
    double mpc_time1 = 0;
    double mpc_time2 = 0;
    for (int i = 0; i < runs; i++)
    {
      std::vector<TEG::DecryptionShare> dec_shares(batch_size);
      for (int j = 0; j < batch_size; j++)
      {
        PendingEntry entry = this->l_pending.pop();
        auto start = std::chrono::high_resolution_clock::now();
        TEG::DecryptionShare share =
            el_gamal.share_c1_and_get_decryption_share(entry.proof.ciphertext, entry.proof.proof, t);
        // already substracting the decryption share from c2 to save an ECC addition in MPC
        share.share = entry.proof.ciphertext.c2 - share.share;
        dec_shares[j] = share;
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        insert_entry_time += elapsed.count();
      }
      mpc_ready_queue.pop();
      auto start1 = std::chrono::high_resolution_clock::now();
      mpc_client.send_G1_points(dec_shares, batch_size);
      input_to_mpcs(start1, true, mpc_time1, mpc_time2, oram_ready_fut, mpc_ready_queue, batch_size);
    }
    oram_ready_fut.wait();
    return {insert_entry_time, mpc_time1, mpc_time2};
  }

  BenchmarkInsertEntry HomeOperatorHonest::calc_decryption_shares(BilinearGroup::BN &period, BilinearGroup::BN &msg, int &runs, int &batch_size)
  {
    bigint::init_thread();
    std::future<void> oram_ready_fut = BilinearGroup::pool.push([](int) {});
    SafeQueue<bool> mpc_ready_queue;
    mpc_ready_queue.push(true);

    double insert_entry_time = 0;
    double zkp_time = 0;
    double mpc_time1 = 0;
    double mpc_time2 = 0;
    for (int i = 0; i < runs; i++)
    {

      std::vector<TEG::DecryptionShare> dec_shares(batch_size);
      for (int j = 0; j < batch_size; j++)
      {
        el_gamal::Ciphertext ciphertext = el_gamal.receive_ciphertext(this->tegService);
        auto start = std::chrono::high_resolution_clock::now();
        GS::zkp::GS_Proof proof;
        std::string proof_str = ciphertext.nizk_proof();
        std::vector<uint8_t> buffer(proof_str.begin(), proof_str.end());
        BilinearGroup::Deserializer deserializer(buffer);
        deserializer >> proof;
        G1 c1 = grpc::deserialize_from_string<G1>(ciphertext.c1())[0];
        G1 c2 = grpc::deserialize_from_string<G1>(ciphertext.c2())[0];

        bookkeeping::proof_create_entry_user p_ce = {{c1, c2}, proof};
        std::vector<uint8_t> h = hash_elements(period, msg, p_ce.ciphertext);
        auto start_zkp = std::chrono::high_resolution_clock::now();

        if (this->verify_create_entry_proof(p_ce, h, this->tsps))
        {
          auto end_zkp = std::chrono::high_resolution_clock::now();
          std::chrono::duration<double> elapsed_zkp = end_zkp - start_zkp;
          zkp_time += elapsed_zkp.count();
          int c_id = ciphertext.ciphertext_id();
          TEG::DecryptionShare decryption_share = el_gamal.calc_decryption_share(c1, c_id, t);
          // TEG::DecryptionShare decryption_share = el_gamal.calc_decryption_share(c1, c_id, t);
          dec_shares[j] = decryption_share;
          auto end = std::chrono::high_resolution_clock::now();
          std::chrono::duration<double> elapsed = end - start;
          insert_entry_time += elapsed.count();
        }
        else
        {
          throw std::invalid_argument("zkp not verified in create_entry");
        }
      }
      mpc_ready_queue.pop();
      auto start1 = std::chrono::high_resolution_clock::now();
      mpc_client.send_G1_points(dec_shares, batch_size);
      input_to_mpcs(start1, false, mpc_time1, mpc_time2, oram_ready_fut, mpc_ready_queue, batch_size);
    }
    return {insert_entry_time, mpc_time1, mpc_time2};
  }

  void HomeOperatorBase::input_to_mpcs(std::chrono::_V2::system_clock::time_point &start_mpc1, bool bootstrap, double &mpc_time1, double &mpc_time2, std::future<void> &oram_ready_fut, SafeQueue<bool> &mpc_ready_queue, int &batch_size)
  {

    std::vector<BilinearGroup::BN> x = mpc_client.get_shares(ho_index, batch_size);
    auto end1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed1 = end1 - start_mpc1;
    mpc_time1 += elapsed1.count();
    std::cout << "mpc_time1 for batch: " << mpc_time1 << std::endl;

    mpc_ready_queue.push(true);

    std::vector<BilinearGroup::BN> converted_shares(batch_size);
    for (int i = 0; i < batch_size; i++)
    {
      converted_shares[i] = this->riss.convert_share(x[i]);
    }

    oram_ready_fut.wait();

    oram_ready_fut = BilinearGroup::pool.push([this, &mpc_time2, batch_size, bootstrap, converted_shares](int)
                                              {

                              
                                   auto start = std::chrono::high_resolution_clock::now();
                                      std::vector<BilinearGroup::BN> shares = converted_shares;

                                for (int i = 0; i < batch_size; i++){
  if (bootstrap)
  {
    mpc_client2->bootstrap_send_share(shares[i], ho_index);
  }
  else
  {
    mpc_client2->send_share(shares[i], ho_index);
  }

      } 
        auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    mpc_time2 += elapsed.count(); 
    std::cout << "mpc_time2 for batch: " << mpc_time2 << std::endl; });
  }
} // namespace bookkeeping