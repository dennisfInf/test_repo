#include "crypto/schemes/tsps/setup.h"
#include "crypto/bilinear_group/matrix.h"
#include "crypto/schemes/tsps/matrix_dist.h"
#include "crypto/schemes/tsps/matrix_serializer.h"
#include "crypto/schemes/tsps/protocol.h"
namespace tsps
{
  PublicParameters create_public_params(const uint8_t &k)
  {
    PublicParameters public_params;
    std::cout << "creating pub params" << std::endl;
    BilinearGroup::Matrix<BilinearGroup::BN> A;
    std::future<void> futureA = BilinearGroup::pool.push([&A, &k](int)
                                                         { A = BilinearGroup::sample_matrix_from_D_k(k); });
    BilinearGroup::Matrix<BilinearGroup::BN> B;
    std::future<void> futureB = BilinearGroup::pool.push([&B, &k](int)
                                                         { B = BilinearGroup::sample_matrix_from_D_k(k); });
    BilinearGroup::Matrix<BilinearGroup::BN> U;
    std::future<void> futureU =
        BilinearGroup::pool.push([&U, &k](int)
                                 { U = BilinearGroup::Matrix<BilinearGroup::BN>(k + 1, k + 1); });
    BilinearGroup::Matrix<BilinearGroup::BN> V;
    std::future<void> futureV =
        BilinearGroup::pool.push([&V, &k](int)
                                 { V = BilinearGroup::Matrix<BilinearGroup::BN>(k + 1, k + 1); });
    std::future<void> futureUAV = BilinearGroup::pool.push(
        [&public_params, &A, &U, &V, &futureA, &futureU, &futureV, &k](int)
        {
          futureA.wait();
          std::future<void> futureAG = BilinearGroup::pool.push(
              [&public_params, &k, &A](int)
              { public_params.A = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G2>(A); });
          std::future<void> futureUA = BilinearGroup::pool.push(
              [&public_params, &k, &U, &A, &futureU](int)
              {
                futureU.wait();
                public_params.UA = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G2>(U * A);
              });
          std::future<void> futureUV = BilinearGroup::pool.push(
              [&public_params, &k, &V, &A, &futureV](int)
              {
                futureV.wait();
                public_params.VA = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G2>(V * A);
              });
          futureAG.wait();
          futureUA.wait();
          futureUV.wait();
        });

    std::future<void> futureUBV = BilinearGroup::pool.push(
        [&public_params, &B, &U, &V, &futureB, &futureU, &futureV, &k](int)
        {
          futureB.wait();
          std::future<void> futureBG = BilinearGroup::pool.push(
              [&public_params, &k, &B](int)
              { public_params.B = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G1>(B); });
          std::future<void> futureBtU = BilinearGroup::pool.push(
              [&public_params, &k, &U, &B, &futureU](int)
              {
                futureU.wait();
                public_params.BtU = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G1>(B.transpose() * U);
              });
          std::future<void> futureBtV = BilinearGroup::pool.push(
              [&public_params, &k, &V, &B, &futureV](int)
              {
                futureV.wait();
                public_params.BtV = BilinearGroup::multiply_matrix_with_generator<BilinearGroup::G1>(B.transpose() * V);
              });
          futureBG.wait();
          futureBtU.wait();
          futureBtV.wait();
        });
    futureUBV.wait();
    futureUAV.wait();
    public_params.A.precompute();
    public_params.UA.precompute();
    public_params.VA.precompute();
    public_params.B.precompute();
    public_params.BtU.precompute();
    public_params.BtV.precompute();
    return public_params;
  }
  uint8_t public_parameters_size() { return 6; };

  void Protocol::send_public_parameters()
  {
    for (int i = 0; i < participants.size(); i++)
    {
      // parallelize more?
      BilinearGroup::pool.push(
          [this, i](int)
          {
            this->send_matrix(0, this->pp.A, i);
            this->send_matrix(1, this->pp.UA, i);
            this->send_matrix(2, this->pp.VA, i);
            this->send_matrix(3, this->pp.B, i);
            this->send_matrix(4, this->pp.BtU, i);
            this->send_matrix(5, this->pp.BtV, i);
          });
    }
  }
} // namespace tsps