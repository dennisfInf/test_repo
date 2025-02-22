#ifndef _COMMITMENTS_H_
#define _COMMITMENTS_H_
#include "group.h"
#include "networking/grpc/serialize.h"
#include "protos/threshold_el_gamal.grpc.pb.h"
#include <optional>
namespace Commitments
{
struct Signature
{
  BilinearGroup::G1 r;
  BilinearGroup::BN z;
};

template <typename T> T serialize_signature(const Signature &signature)
{

  T signature_proto;
  signature_proto.set_r(grpc::serialize_to_string(signature.r));
  signature_proto.set_z(grpc::serialize_to_string(signature.z));
  return signature_proto;
};
template <typename T> Signature deserialize_signature(const T &signature)
{
  return Signature{grpc::deserialize_from_string<BilinearGroup::G1>(signature.r())[0],
                   grpc::deserialize_from_string<BilinearGroup::BN>(signature.z())[0]};
};

struct DKG__Commitment
{
  int player_id;
  std::vector<BilinearGroup::G1> commitments;
};

std::vector<BilinearGroup::G1> generate_commitments(const BilinearGroup::BN &secret,
                                                    const std::vector<BilinearGroup::BN> polynomial, const uint8_t &t);

BilinearGroup::BN generate_challenge(const uint8_t id, std::string const context,
                                     const BilinearGroup::G1 secret_commitment, const BilinearGroup::G1 r_commitment);

class DKG_Proposed_Commitments
{
public:
  DKG_Proposed_Commitments(){};
  DKG_Proposed_Commitments(const uint8_t &player_id, const std::vector<BilinearGroup::G1> commitments,
                           const Signature zkp)
      : player_id(player_id), commitments(commitments), zkp(zkp){};
  template <typename T> DKG_Proposed_Commitments(const T &commitment_proto)
  {
    this->player_id = commitment_proto.player_id();

    this->zkp = deserialize_signature(commitment_proto.signature());

    this->commitments = grpc::deserialize_from_string<BilinearGroup::G1>(commitment_proto.commitments());
  }
  std::optional<DKG__Commitment> verify_zkp(const BilinearGroup::BN &challenge);
  DKG__Commitment own_commitment();
  BilinearGroup::BN generate_challenge(const std::string &context);
  template <typename T, typename U> T serialize_to_proto() const
  {
    T coms_proto;
    coms_proto.set_player_id(this->player_id);
    *coms_proto.mutable_signature() = serialize_signature<U>(this->zkp);
    std::string commitments_string = "";
    for (uint8_t i = 0; i < this->commitments.size(); i++)
    {
      commitments_string += grpc::serialize_to_string(this->commitments[i]);
    }
    coms_proto.set_commitments(commitments_string);
    return coms_proto;
  }
  std::optional<Commitments::DKG__Commitment> verify(const std::string &context);

private:
  uint8_t player_id;
  std::vector<BilinearGroup::G1> commitments;
  Signature zkp;
};

}; // namespace Commitments
#endif