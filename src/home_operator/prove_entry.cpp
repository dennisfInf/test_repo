#include "home_operator/protocol.h"
#include "crypto/schemes/tsps/verify.h"
#include "user/protocol.h"
#include "crypto/bookkeeping_proofs/prove_entry/verifier.h"
#include "crypto/bookkeeping_proofs/prove_entry/out_types.hpp"

namespace bookkeeping
{
    bool HomeOperator::prove_entry(proof_prove_entry &ppe, tsps::Protocol *tsps)
    {
        std::vector<BilinearGroup::G1> message = {BilinearGroup::G1::koblitz_encode_message(ppe.addr), ppe.pk_u};

        if (tsps::verify(this->get_public_parameters(tsps), message, tsps->get_public_key(), ppe.threshold_signature))
        {
            std::vector<uint8_t> h = hash_elements(ppe.period, ppe.message, ppe.ciphertext);
            if (this->bls_sig.verify_signature(h, ppe.sig_entry, this->bls_sig.get_public_key()))
            {
                GS::prove_entry::GS_Input_Public input;
                input.addr = {BilinearGroup::G1::koblitz_encode_message(ppe.addr)};
                input.ct1 = {ppe.ciphertext.c1};
                input.ct2 = {ppe.ciphertext.c2};
                input.ek = {this->get_public_keys(tsps).ek_all};
                input.pk = {ppe.pk_u};
                if (GS::prove_entry::batch_verify(this->crs_nizk, ppe.proof, input))
                {
                    // Find pair in Lkeys
                    LKey target = {ppe.pk_u, ppe.addr};
                    auto it = std::find(this->l_keys.begin(), this->l_keys.end(), target);
                    if (it != this->l_keys.end())
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}