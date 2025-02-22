#include "user/protocol.h"
#include "crypto/bookkeeping_proofs/prove_entry/out_types.hpp"

namespace bookkeeping
{
    proof_prove_entry User::create_proof_for_prove_entry(Entry &entry)
    {
        GS::prove_entry::GS_Input proof_input;
        proof_input.addr = {BilinearGroup::G1::koblitz_encode_message(this->creds.addr)};
        proof_input.ct1 = {entry.ct_u.c.c1};
        proof_input.ct2 = {entry.ct_u.c.c2};
        proof_input.ek = {this->ek_all};
        proof_input.rinv = {BilinearGroup::G2::get_gen() * -entry.ct_u.r};
        proof_input.pk = {this->bls_sig.get_public_key()};
        proof_input.sk = {-this->bls_sig.get_secret_key() * BilinearGroup::G2::get_gen()};
        BilinearGroup::BN period = {0};
        return {entry.ct_u.c, entry.sig_entry, entry.message, this->creds.addr, period,
                this->creds.threshold_signature, this->bls_sig.get_public_key(), GS::prove_entry::prove(this->crs_nizk, proof_input)};
    };
};
