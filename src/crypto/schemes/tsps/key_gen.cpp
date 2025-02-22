#include "crypto/schemes/tsps/key_gen.h"
#include "crypto/schemes/secret_sharing/commitments.h"
#include "crypto/schemes/secret_sharing/secret_sharing.h"
#include "crypto/schemes/secret_sharing/share.h"
#include "crypto/schemes/tsps/matrix_dist.h"
#include "crypto/schemes/tsps/protocol.h"
#include "networking/client.h"

namespace tsps
{

void Protocol::run_dkg()
{
  // unsecure contexts, should be replaced with secure contexts
  std::vector<std::vector<std::string>> contexts(l + 1, std::vector<std::string>(k + 1));
  std::vector<std::vector<Participants::ThreadSafeSecretSharing>> secret_sharings(
      l + 1, std::vector<Participants::ThreadSafeSecretSharing>(k + 1, Participants::ThreadSafeSecretSharing(n)));
  std::vector<std::future<void>> futures;

  for (int i = 0; i < l + 1; i++)
  {
    for (int j = 0; j < k + 1; j++)
    {
      contexts[i][j] = "context" + i + j;
      futures.push_back(BilinearGroup::pool.push(
          [this, i, j, &contexts, &secret_sharings](int)
          {
            this->share_of_coefficient(i, j, contexts[i][j], secret_sharings[i][j]);
            for (int z = 0; z < n - 1; z++)
            {
              tsps::Commited_Share com_share = service->pop_queue();
              int row = com_share.row();
              int col = com_share.col();
              if (secret_sharings[row][col].received_enough_shares(n))
              {
                std::cout << "received enough shares.." << std::endl;
                continue;
              }
              else
              {
                secret_sharings[row][col].add_com_share(
                    Participants::handleCommittedShare(com_share, contexts[row][col], my_index));
                if (secret_sharings[row][col].received_enough_shares(n))
                {

                  BilinearGroup::BN secret = secret_sharings[row][col].get_secret(n);
                  this->key.set_secret_share(row, col, secret);
                }
              }
            }
          }));
    }
  }
  for (auto &f : futures)
  {
    f.wait();
  }
}

void Protocol::share_of_coefficient(const uint8_t &row, const uint8_t &column, std::string &context,
                                    Participants::ThreadSafeSecretSharing &secret_sharing)
{
  std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> poly =
      secret_sharing.init(n, t, my_index, context);
  Participants::Com_Shares my_share =
      Participants::Com_Shares{std::get<0>(poly).own_commitment(), std::get<1>(poly)[my_index - 1]};
  secret_sharing.add_com_share(my_share);
  this->send_commited_shares(poly, row, column);
}

void Protocol::send_commited_shares(
    std::tuple<Commitments::DKG_Proposed_Commitments, std::vector<Participants::Share>> &poly, const uint8_t &row,
    const uint8_t &column)
{

  Commitments::DKG_Proposed_Commitments coms = std::get<0>(poly);
  std::vector<Participants::Share> shares = std::get<1>(poly);

  tsps::Proposed_Commitment coms_proto = coms.serialize_to_proto<tsps::Proposed_Commitment, tsps::Signature>();
  int share_index = 0;
  for (int i = 0; i < participants.size(); i++)
  {

    tsps::Commited_Share comm_share;
    comm_share.mutable_commitment()->CopyFrom(coms_proto);
    if (i == my_index - 1)
    {
      share_index++;
    }
    comm_share.mutable_share()->CopyFrom(shares[share_index].serialize_to_proto<tsps::Share>());
    comm_share.set_col(column);
    comm_share.set_row(row);
    Networking::Stub<tsps::DKG> stub = participants[i].createStub<tsps::DKG>();
    stub.send<tsps::Commited_Share, tsps::Response>(
        comm_share, comm_share.share().receiver_index(),
        [](tsps::DKG::Stub *stub, grpc::ClientContext *context, tsps::Commited_Share *request, tsps::Response *response)
        {
          grpc::Status status = stub->Send_Commited_Shares(context, *request, response);
          return status;
        });
    share_index++;
  }
}

} // namespace tsps