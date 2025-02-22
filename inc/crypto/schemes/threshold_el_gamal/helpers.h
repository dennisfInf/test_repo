#include "crypto/schemes/secret_sharing/share.h"
#include "group.h"
#include "protocol.h"
#include "protos/threshold_el_gamal.grpc.pb.h"
#include <vector>
namespace Participants
{
std::vector<uint8_t> xor_arrays(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);
std::string convert_vec_uint8_to_string(std::vector<uint8_t> vec);
std::string convert_array_to_string(uint8_t *buffer, size_t capacity);

}; // namespace Participants