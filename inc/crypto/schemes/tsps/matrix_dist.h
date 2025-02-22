#pragma once

#include "group.h"
#include "matrix.h"

namespace BilinearGroup
{
Matrix<BN> sample_matrix_from_D_k(size_t rows);
std::tuple<Matrix<BN>,Matrix<BN>> luDecomposition(Matrix<BN> &matrix);
BN calculate_determinant_from_lu(Matrix<BN> &l , Matrix<BN> &u);

} // namespace BilinearGroup