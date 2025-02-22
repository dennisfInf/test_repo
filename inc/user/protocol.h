#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/bls_sig/scheme.h"
#include "crypto/schemes/tsps/setup.h"
#include "crypto/schemes/tsps/sign.h"
#include "user/structs.h"
namespace bookkeeping
{
  class User
  {
  public:
    User(const BilinearGroup::G1 ek_all, const BilinearGroup::Matrix<BilinearGroup::G2> vk_all,
         const BilinearGroup::G1 vk_ho, tsps::PublicParameters crs_tsps, GS::CRS crs_nizk)
        : ek_all(ek_all), vk_all(vk_all), vk_ho(vk_ho), crs_tsps(crs_tsps), crs_nizk(crs_nizk)
    {

      BilinearGroup::BN sk_u = BilinearGroup::BN::rand();
      this->bls_sig = BLS::Signatures(sk_u, BilinearGroup::G1::get_gen() * sk_u);
    };
    proof_prove_entry create_proof_for_prove_entry(Entry &entry);
    proof_sk_u create_proof_for_sk_u();
    bool finalize_registration(BilinearGroup::FP addr, tsps::SignatureM threshold_signature);
    proof_create_entry create_proof_for_create_entry(BilinearGroup::BN period, BilinearGroup::BN message);
    Entry finalize_create_entry(BilinearGroup::BN message, Participants::ciphertext_r ct_r, BilinearGroup::G2 signature_ho,
                                std::vector<uint8_t> hash);

  private:
    BLS::Signatures bls_sig;
    BilinearGroup::G1 ek_all;
    BilinearGroup::Matrix<BilinearGroup::G2> vk_all;
    BilinearGroup::G1 vk_ho;
    std::vector<Entry> entries;
    std::mutex entries_mtx;
    tsps::PublicParameters crs_tsps;
    credentials creds; // Credentials
    GS::CRS crs_nizk;  // CRS for NIZK
    //  List of receipts for loogbook entries
  };

  std::vector<uint8_t> hash_elements(BilinearGroup::BN period, BilinearGroup::BN message, Participants::ciphertext ct_u);
}; // namespace bookkeeping