#include "crypto/schemes/tsps/sign.h"
#include "crypto/bilinear_group/group.h"
#include "crypto/schemes/secret_sharing/polynomial.h"
#include <iostream>

namespace tsps
{
  SignatureM parSign(const PublicParameters &pp, const BilinearGroup::Matrix<BilinearGroup::BN> &sk_i,
                     std::vector<BilinearGroup::G1> m)
  {

    SignatureM sig;
    std::vector<BilinearGroup::BN> r_i(sk_i.cols() - 1); // Create a vector of N elements
    std::generate(r_i.begin(), r_i.end(), []()
                  { return BilinearGroup::BN::rand(); });
    BilinearGroup::Matrix<BilinearGroup::BN> r_i_t =
        BilinearGroup::Matrix<BilinearGroup::BN>(BilinearGroup::BN::get_infty(), r_i);
    BilinearGroup::BN tau = BilinearGroup::hash_G1_elements<BilinearGroup::BN>(m);
    m.insert(m.begin(), BilinearGroup::G1::get_gen());
    BilinearGroup::Matrix<BilinearGroup::G1> m_t =
        BilinearGroup::Matrix<BilinearGroup::G1>(BilinearGroup::G1::get_infty(), m);
    // B^T * U + B^T * V * tau = B^T * (U + V * tau) = B^T * (U + tau * V)
    sig.sig_1 = (m_t * sk_i) + (r_i_t * (pp.BtU + (pp.BtV * tau)));
    sig.sig_2 = r_i_t * pp.B.transpose();
    sig.sig_3 = sig.sig_2 * tau;
    sig.sig_4 = BilinearGroup::G2::get_gen() * tau;
    return sig;
  }

  // n is not the amount of parties, it should be greater than the threshold
  SignatureM combineSign(uint8_t &n, std::vector<PartialSignature> &sigs)
  {
    SignatureM sig;
    BilinearGroup::BN la_grange_for_sig_0 = Polynomial::get_lagrange_coeff(BilinearGroup::BN(0), sigs[0].party_id, n);
    sig.sig_1 = sigs[0].signature.sig_1 * la_grange_for_sig_0;
    sig.sig_2 = sigs[0].signature.sig_2 * la_grange_for_sig_0;
    sig.sig_3 = sigs[0].signature.sig_3 * la_grange_for_sig_0;

    for (int i = 1; i < sigs.size(); i++)
    {
      BilinearGroup::BN la_grange = Polynomial::get_lagrange_coeff(BilinearGroup::BN(0), sigs[i].party_id, n);
      sig.sig_1 = sig.sig_1 + (sigs[i].signature.sig_1 * la_grange);
      sig.sig_2 = sig.sig_2 + (sigs[i].signature.sig_2 * la_grange);
      sig.sig_3 = sig.sig_3 + (sigs[i].signature.sig_3 * la_grange);
    }
    sig.sig_4 = sigs[0].signature.sig_4;

    return sig;
  }
} // namespace tsps