#pragma once
#include "deserializer.h"
#include "serializer.h"
#include <array>
#include <iostream>
#include <type_traits>

namespace GS
{
namespace util
{

template <size_t Rows, size_t Cols, typename T> struct TMatrix
{
  using element_type = T;

  std::array<T, Rows * Cols> m_data;

  void serialize_to(BilinearGroup::Serializer &serializer) const { serializer.serialize(m_data); }

  void deserialize_from(BilinearGroup::Deserializer &deserializer) { deserializer.deserialize(m_data); }

  template <typename... Args> TMatrix(Args... args) : m_data({args...})
  {
    constexpr auto length = sizeof...(args);
    static_assert(length == (Rows * Cols), "Length of initializer List must match Matrix Dimension");
  }

  TMatrix() = default;

  TMatrix(T const &el) : m_data()
  {
    for (auto pos = 0; pos < (Rows * Cols); ++pos)
    {
      m_data[pos] = el;
    }
  }

  static auto get_id()
  {
    TMatrix<Rows, Cols, T> result;
    for (size_t r = 0; r < Rows; ++r)
    {
      for (size_t c = 0; c < Cols; ++c)
      {
        if (r == c)
        {
          result(r, c) = T(1);
        }
        else
        {
          result(r, c) = T(0);
        }
      }
    }
    return result;
  }

  std::array<T, Rows> get_col(size_t j) const
  {
    std::array<T, Rows> result = {};
    for (size_t c = 0; c < Rows; ++c)
    {
      result[c] = this->m_data.at(c * Cols + j);
    }
    return result;
  }

  std::array<T, Cols> get_row(size_t i) const
  {
    std::array<T, Cols> result = {};
    for (size_t c = 0; c < Cols; ++c)
    {
      result[c] = this->m_data.at(i * Cols + c);
    }
    return result;
  }

  auto operator+=(TMatrix<Rows, Cols, T> const &other)
  {
    for (size_t r = 0; r < Rows; r++)
    {
      for (size_t c = 0; c < Cols; c++)
      {
        (*this)(r, c) += other(r, c);
      }
    }
    return *this;
  }

  auto operator+(TMatrix<Rows, Cols, T> const &other) const
  {
    TMatrix<Rows, Cols, T> result;
    for (size_t r = 0; r < Rows; r++)
    {
      for (size_t c = 0; c < Cols; c++)
      {
        result(r, c) = (*this)(r, c) + other(r, c);
      }
    }
    return result;
  }

  auto operator-(TMatrix<Rows, Cols, T> const &other) const
  {
    TMatrix<Rows, Cols, T> result;
    for (size_t r = 0; r < Rows; r++)
    {
      for (size_t c = 0; c < Cols; c++)
      {
        result(r, c) = (*this)(r, c) - other(r, c);
      }
    }
    return result;
  }

  template <size_t Other_Cols, typename Other_T> auto operator*(TMatrix<Cols, Other_Cols, Other_T> const &other) const
  {

    using result_element_type = decltype((*this)(0, 0) * other(0, 0));

    TMatrix<Rows, Other_Cols, result_element_type> result;

    for (size_t i = 0; i < Rows; ++i)
    {
      for (size_t j = 0; j < Other_Cols; ++j)
      {
        result_element_type acc(0);
        auto row = this->get_row(i);
        auto col = other.get_col(j);
        for (size_t k = 0; k < Cols; ++k)
        {
          acc += row.at(k) * col.at(k);
        }
        result(i, j) = acc;
      }
    }
    return result;
  }

    void precompute() const
  {
    for (size_t row = 0; row < Rows; ++row)
    {
      for (size_t col = 0; col < Cols; ++col)
      {
        (*this)(row, col).precompute();
      }
    }
  }

  auto transpose() const
  {
    TMatrix<Cols, Rows, T> result;
    for (auto r = size_t(0); r < Rows; r++)
    {
      for (auto c = size_t(0); c < Cols; c++)
      {
        result(c, r) = (*this)(r, c);
      }
    }
    return result;
  }

  T operator()(size_t row, size_t col) const { return m_data.at(row * Cols + col); }

  T &operator()(size_t row, size_t col) { return m_data.at(row * Cols + col); }
};

template <typename T> using TVec2 = TMatrix<2, 1, T>;

template <size_t Rows, size_t Cols, typename T>
bool operator==(TMatrix<Rows, Cols, T> const &left, TMatrix<Rows, Cols, T> const &right)
{

  for (size_t i = 0; i < Rows; ++i)
  {
    for (size_t j = 0; j < Cols; ++j)
    {
      if (left(i, j) != right(i, j))
      {
        return false;
      }
    }
  }
  return true;
}

template <size_t Rows, size_t Cols, typename T> std::ostream &operator<<(std::ostream &out, TMatrix<Rows, Cols, T> m)
{
  std::cout << "Printing TMatrix<" << Rows << "," << Cols << "," << typeid(T).name() << ">" << '\n';
  for (size_t i = 0; i < Rows; i++)
  {
    for (size_t j = 0; j < Cols; j++)
    {
      std::cout << " " << std::to_string(m(i, j)) << " ";
    }
    std::cout << '\n';
  }
  return out;
}

/* template<typename Other_T, typename ElementType, size_t Rows, size_t Cols> */
/*   inline auto operator*(Other_T const& factor, */
/* TMatrix<Rows, Cols, ElementType> const& m) -> auto */
/*   { */
/*     auto result = m * factor; */
/*     return result; */
/*   } */
} // namespace util
} // namespace GS
