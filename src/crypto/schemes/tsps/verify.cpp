#include "crypto/schemes/tsps/verify.h"
#include "crypto/bilinear_group/group.h"
#include "crypto/bilinear_group/matrix.h"
#include <iostream>

namespace tsps
{
  bool verify(const PublicParameters &public_params, std::vector<BilinearGroup::G1> message,
              const BilinearGroup::Matrix<BilinearGroup::G2> &public_key, const SignatureM &signature)
  {
    BilinearGroup::Matrix<BilinearGroup::GT> left =
        BilinearGroup::calculate_pairing_matrix(signature.sig_1, public_params.A);
    message.insert(message.begin(), BilinearGroup::G1::get_gen());
    BilinearGroup::Matrix<BilinearGroup::G1> message_matrix =
        BilinearGroup::Matrix<BilinearGroup::G1>(BilinearGroup::G1::get_infty(), message);

    BilinearGroup::Matrix<BilinearGroup::GT> m_vk_pairing =
        BilinearGroup::calculate_pairing_matrix(message_matrix, public_key);

    BilinearGroup::Matrix<BilinearGroup::GT> sig_2_UA_pairing =
        BilinearGroup::calculate_pairing_matrix(signature.sig_2, public_params.UA);

    BilinearGroup::Matrix<BilinearGroup::GT> sig_3_VA_pairing =
        BilinearGroup::calculate_pairing_matrix(signature.sig_3, public_params.VA);

    if (left == m_vk_pairing + sig_2_UA_pairing + sig_3_VA_pairing)
    {
      BilinearGroup::Matrix<BilinearGroup::GT> sig_2_sig_4_pairing =
          BilinearGroup::calculate_pairing_matrix_element_wise(signature.sig_2, signature.sig_4);
      BilinearGroup::Matrix<BilinearGroup::GT> sig_3_1_pairing =
          BilinearGroup::calculate_pairing_matrix_element_wise(signature.sig_3, BilinearGroup::G2::get_gen());
      if (sig_2_sig_4_pairing == sig_3_1_pairing)
      {
        return true;
      }
      else
      {
        std::cout << "second check failed" << std::endl;
        return false;
      }
    }
    else
    {
      std::cout << "first check failed" << std::endl;
      return false;
    }
  }

} // namespace tsps