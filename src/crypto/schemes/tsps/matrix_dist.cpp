#include "crypto/schemes/tsps/matrix_dist.h"
#include "iostream"

namespace BilinearGroup
{
#include <vector>

std::tuple<Matrix<BN>, Matrix<BN>> luDecomposition(Matrix<BN> &matrix)
{
  size_t rows = matrix.rows();
  Matrix<BN> lower = Matrix(rows, rows, BN::get_infty());
  Matrix<BN> upper = Matrix(rows, rows, BN::get_infty());

  for (int i = 0; i < rows; i++)
  {
    for (int k = i; k < rows; k++)
    {
      BN sum = 0;
      for (int j = 0; j < i; j++)
        sum += (lower(i, j) * upper(j, k));
      upper(i, k) = matrix(i, k) - sum;
    }

    for (int k = i; k < rows; k++)
    {
      if (i == k)
        lower(i, i) = 1; // Diagonal values are 1 for lower
      else
      {
        BN sum = 0;
        for (int j = 0; j < i; j++)
          sum += (lower(k, j) * upper(j, i));
        lower(k, i) = (matrix(k, i) - sum) / upper(i, i);
      }
    }
  }

  return {lower, upper};
}

BN calculate_determinant_from_lu(Matrix<BN> &l, Matrix<BN> &u)
{
  BN det = 1;
  for (int i = 0; i < l.rows(); i++)
  {
    det *= l(i, i);
  }
  for (int i = 0; i < u.rows(); i++)
  {
    det *= u(i, i);
  }
  return det;
}

Matrix<BN> sample_matrix_from_D_k(size_t rows)
{
  Matrix<BN> A;
  BN det = BN::get_infty();
  do
  {
    A = Matrix<BN>(rows, rows);
    std::tuple<Matrix<BN>, Matrix<BN>> lu = luDecomposition(A);
    det = calculate_determinant_from_lu(std::get<0>(lu), std::get<1>(lu));
  } while (det == 0);
  std::vector<BilinearGroup::BN> row(rows); // Create a vector of col elements
  std::generate(row.begin(), row.end(), []() { return BilinearGroup::BN::rand(); });
  A.add_row(Matrix<BN>(BilinearGroup::Matrix<BilinearGroup::BN>(BilinearGroup::BN::get_infty(), row)));
  return A;
}

} // namespace BilinearGroup