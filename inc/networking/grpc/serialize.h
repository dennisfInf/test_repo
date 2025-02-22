
#pragma once
#include <string>

namespace grpc
{
template <typename T> std::string serialize_to_string(const T &t)
{
  int capacity = t.size();
  uint8_t *buffer = new uint8_t[capacity];
  t.serialize(buffer, capacity);
  std::string buffer_as_string(reinterpret_cast<char *>(buffer), capacity);
  delete[] buffer;

  // Prepend the size of the serialized object to the string
  std::string size_as_string = std::to_string(capacity);
  return size_as_string + ":" + buffer_as_string;
}

template <typename T> std::vector<T> deserialize_from_string(std::string string)
{
  std::vector<T> objects;
  size_t pos = 0;

  while (pos < string.size())
  {
    // Extract the size of the next object
    size_t delimiter_pos = string.find(":", pos);
    int size = std::stoi(string.substr(pos, delimiter_pos - pos));

    // Extract the serialized object
    std::string object_string = string.substr(delimiter_pos + 1, size);
    uint8_t *buffer = new uint8_t[size];
    std::copy(object_string.begin(), object_string.end(), buffer);

    // Deserialize the object and add it to the vector
    T type;
    type.deserialize(buffer);
    objects.push_back(type);

    delete[] buffer;
    pos = delimiter_pos + 1 + size;
  }

  return objects;
}

} // namespace grpc