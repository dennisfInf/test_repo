#pragma once
#include "crypto/bilinear_group/matrix.h"
#include "networking/grpc/serialize.h"
#include "protos/tsps.grpc.pb.h"

namespace tsps
{
template <typename T> std::string serialize_to_proto(const std::vector<T> &vec)
{
  std::string data_string = "";

  for (uint8_t i = 0; i < vec.size(); i++)
  {
    data_string += grpc::serialize_to_string(vec[i]);
  }
  return data_string;
}

template <typename T> tsps::Matrix serialize_to_proto(const int &matrix_variant, const BilinearGroup::Matrix<T> &matrix)
{
  std::vector<T> m_data = matrix.to_vector();
  tsps::Matrix matrix_proto;
  matrix_proto.set_matrix_variant(matrix_variant);
  matrix_proto.set_matrix(serialize_to_proto(m_data));
  return matrix_proto;
}

template <typename T>
BilinearGroup::Matrix<T> deserialize_from_proto(const std::string &matrix_string, uint8_t rows, uint8_t cols)
{
  std::vector<T> m_data;
  m_data = grpc::deserialize_from_string<T>(matrix_string);

  T neutral_element;
  if constexpr (std::is_same<T, BilinearGroup::GT>::value)
  {
    neutral_element = T::get_unity();
  }
  else
  {
    neutral_element = T::get_infty();
  }
  return BilinearGroup::Matrix<T>(rows, cols, neutral_element, m_data);
}

} // namespace tsps