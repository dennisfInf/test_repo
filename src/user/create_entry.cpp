#include "crypto/bookkeeping_proofs/create_entry/out_types.hpp"
#include "crypto/schemes/bls_sig/scheme.h"
#include "crypto/schemes/threshold_el_gamal/participant.h"
#include "user/protocol.h"
namespace bookkeeping
{
  // Creates a proof for the user's logbook entry
  proof_create_entry User::create_proof_for_create_entry(BilinearGroup::BN period, BilinearGroup::BN message)
  {

    // encrypts the user's address with the public key of the threshold el gamal scheme of the operators);
    Participants::ciphertext_r c_r = Participants::encrypt(this->creds.addr, this->ek_all);
    // hashes the period, the message and the ciphertext
    std::vector<uint8_t> hash = hash_elements(period, message, c_r.c);
    // signs the hash with the user's secret bls key
    BLS::Signature signature = bls_sig.sign_message(hash);
    GS::zkp::GS_Input proof_input;
    // encodes the addr with the koblitz encoding to a point in G1
    proof_input.addr = {BilinearGroup::G1::koblitz_encode_message(this->creds.addr)};
    proof_input.ct1 = {c_r.c.c1};
    proof_input.ct2 = {c_r.c.c2};
    proof_input.ek = {this->ek_all};

    // inverts r first, which is required for our gs proof
    proof_input.rinv = {BilinearGroup::G2::get_gen() * -c_r.r};

    // the rest here, only sets the values of the proof input. We used a GS transpiler made in Julian Herr's master thesis to automatically
    //  generate the code for the proofs by only entering the formulas, which requires an input object
    proof_input.fosig = {this->creds.threshold_signature.sig_4};
    proof_input.ppA11 = {this->crs_tsps.A(0, 0)};
    proof_input.ppA21 = {this->crs_tsps.A(1, 0)};

    proof_input.ppB11 = {this->crs_tsps.B(0, 0)};
    proof_input.ppB21 = {this->crs_tsps.B(1, 0)};

    proof_input.ppBtU11 = {this->crs_tsps.BtU(0, 0)};
    proof_input.ppBtU12 = {this->crs_tsps.BtU(0, 1)};

    proof_input.ppBtV11 = {this->crs_tsps.BtV(0, 0)};
    proof_input.ppBtV12 = {this->crs_tsps.BtV(0, 1)};

    proof_input.ppUA11 = {this->crs_tsps.UA(0, 0)};
    proof_input.ppUA21 = {this->crs_tsps.UA(1, 0)};

    proof_input.ppVA11 = {this->crs_tsps.VA(0, 0)};
    proof_input.ppVA21 = {this->crs_tsps.VA(1, 0)};

    proof_input.vk11 = {this->vk_all(0, 0)};
    proof_input.vk21 = {this->vk_all(1, 0)};
    proof_input.vk31 = {this->vk_all(2, 0)};

    proof_input.siguser = {signature.sig};
    proof_input.fsig11 = {this->creds.threshold_signature.sig_1(0, 0)};
    proof_input.fsig12 = {this->creds.threshold_signature.sig_1(0, 1)};

    proof_input.ssig11 = {this->creds.threshold_signature.sig_2(0, 0)};
    proof_input.ssig12 = {this->creds.threshold_signature.sig_2(0, 1)};

    proof_input.tsig11 = {this->creds.threshold_signature.sig_3(0, 0)};
    proof_input.tsig12 = {this->creds.threshold_signature.sig_3(0, 1)};
    proof_input.h = {signature.msg};
    proof_input.pk = {this->bls_sig.get_public_key()};
    return {c_r, hash, GS::zkp::prove(this->crs_nizk, proof_input)};
  };

  // Verifies the signature of the home operator and if it is valid, adds the entry to the list of entries
  Entry User::finalize_create_entry(BilinearGroup::BN message, Participants::ciphertext_r ct_r,
                                    BilinearGroup::G2 signature_ho, std::vector<uint8_t> hash)
  {
    if (BLS::Signatures::verify_signature(hash, signature_ho, this->vk_ho))
    {
      Entry entry = {message, ct_r, signature_ho};
      entries.push_back(entry);
      return entry;
    }
    return {};
  }

  // Hashes the period, the message and the ciphertext
  std::vector<uint8_t> hash_elements(BilinearGroup::BN period, BilinearGroup::BN message, Participants::ciphertext ct_u)
  {
    uint8_t period_size = period.size();
    uint8_t message_size = message.size();
    uint8_t c1_size = ct_u.c1.buffer_size();
    uint8_t c2_size = ct_u.c2.buffer_size();
    // Creates a buffer for all elements
    uint8_t *buffer = new uint8_t[period_size + message_size + c1_size + c2_size + 1];
    // The futures are used to parallelize the serialization of the elements. Here first an element is serialized to a buffer and then
    // copied to the buffer for all elements at the appropiate position to avoid overlapping
    std::vector<std::future<void>> futures;
    futures.push_back(BilinearGroup::pool.push(
        [buffer, &period_size, &period](int)
        {
          uint8_t *period_buffer = new uint8_t[period_size];
          period.serialize(period_buffer, period_size);
          std::copy(period_buffer, period_buffer + period_size, buffer);
          delete[] period_buffer;
        }));

    futures.push_back(BilinearGroup::pool.push(
        [buffer, &message_size, &message, &period_size](int)
        {
          uint8_t *message_buffer = new uint8_t[message_size];
          message.serialize(message_buffer, message_size);
          // copies the message buffer to the buffer
          std::copy(message_buffer, message_buffer + message_size, buffer + period_size);
          delete[] message_buffer;
        }));

    futures.push_back(BilinearGroup::pool.push(
        [buffer, &c1_size, &c1 = ct_u.c1, &message_size, &period_size](int)
        {
          uint8_t *c1_buffer = new uint8_t[c1_size];
          c1.serialize(c1_buffer, c1_size);
          std::copy(c1_buffer, c1_buffer + c1_size, buffer + period_size + message_size);
          delete[] c1_buffer;
        }));

    uint8_t *c2_buffer = new uint8_t[c2_size];
    ct_u.c2.serialize(c2_buffer, c2_size);
    std::copy(c2_buffer, c2_buffer + c2_size, buffer + period_size + message_size + c1_size);
    delete[] c2_buffer;

    for (auto &f : futures)
    {
      f.wait();
    }
    // Uses the hash function specified in the relic configuration, which is sha256, if it is left unchanged
    std::vector<uint8_t> hash = BilinearGroup::hash(buffer, period_size + message_size + c1_size + c2_size);
    delete[] buffer;
    return hash;
  }

} // namespace bookkeeping