#include "networking/mpc/connect.h"
#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "Math/gfpvar.h"
#include "Math/bigint.h"
#include "Math/gfpvar.cpp"
#include "networking/mpc/serialization.h"

namespace MPC
{
  // Set's up the sockets to each participant in the MPC and sends a zero or one to indicate if the client is the bootstrapper.
  // This is needed because the MPC has to know, which input is coming from the boostrapper.
  void MPC::MPCClient::setup_sockets(int n_parties, int bootstrapper)
  {
    auto &sockets = client.sockets;
    for (int i = 0; i < n_parties; i++)
    {
      octetStream os;
      os.store(bootstrapper);
      os.Send(sockets[i]);
    }

    cout << "Finish setup socket connections to SPDZ engines." << endl;
  };

  // gets the prime number of the mpc
  bigint MPC::MPCClient::get_prime_number()
  {
    int type = client.specification.get<int>();
    switch (type)
    {
    case 'p':
    {
      return client.specification.get<bigint>();
      break;
    }
    default:
      cerr << "Type " << type << " not implemented";
      exit(1);
    }
  }

  // initializes the field with the prime number from the MPC
  void MPC::MPCClient::init_field()
  {
    bigint prime = this->get_prime_number();
    gfp::init_field(prime);
  }

  // Sends an additive share to MPC_2
  void MPC::MPCClient::send_share(BilinearGroup::BN &share, int index)
  {
    // Converts the BN to a gfpvar

    gfpvar_<1, 6> conv_share = MPC::conv_bn_to_gfpvar(share);
    // Sends the converted share
    this->one_run<gfpvar_<1, 6>>({conv_share});
    // Waits for the output of the mpc. Only used to know, if the MPC is actually finished.
    this->client.receive_outputs<gfpvar_<1, 6>>(1);
  }

  void MPC::MPCClient::bootstrap_send_share(BilinearGroup::BN &share, int index)
  {
    // Bootstrapper sends the message, that is inserted into the logbook with it's converted share to MPC_2 here
    gfpvar_<1, 6> conv_share = MPC::conv_bn_to_gfpvar(share);
    gfpvar_<1, 6> message_1 = gfpvar_<1, 6>(1389239932);
    gfpvar_<1, 6> message_2 = gfpvar_<1, 6>(1337288233);
    this->one_run<gfpvar_<1, 6>>({conv_share, message_1, message_2});

    this->client.receive_outputs<gfpvar_<1, 6>>(1);
  }
  void MPC::MPCClient::check_if_finished()
  {
    // just waits to get an output returned from the MPC.
    client.receive_outputs<gfp>(1);
  }
  // sends a G1 point to MPC_1
  void MPC::MPCClient::send_G1_points(std::vector<TEG::DecryptionShare> &points, int &batch_size)
  {
    std::vector<gfp> coordinates(batch_size * 2);
    // Gets the coordinates of the point and normalizes it, if not already done.
    for (int i = 0; i < points.size(); i++)
    {
      std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> coords = points[i].share.get_coordinates();
      coordinates[i] = MPC::deserialize_bytes(std::get<0>(coords));
      coordinates[batch_size + i] = MPC::deserialize_bytes(std::get<1>(coords));
    }
    // Sends the x and y coordinates
    this->one_run<gfp>(coordinates);
  }

  void MPC::MPCClient::send_G1_points_with_C(std::vector<TEG::DecryptionShare> &points, std::vector<BilinearGroup::G1> &ciphertexts, int &batch_size)
  {
    std::vector<gfp> coordinates(batch_size * 4);
    // Gets the coordinates of the point and normalizes it, if not already done.
    for (int i = 0; i < points.size(); i++)
    {
      ciphertexts[i].norm();
      points[i].share.norm();
      std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> coords = points[i].share.get_coordinates();
      std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> coords_c = ciphertexts[i].get_coordinates();
      coordinates[i] = MPC::deserialize_bytes(std::get<0>(coords));
      coordinates[batch_size + i] = MPC::deserialize_bytes(std::get<1>(coords));
      coordinates[batch_size * 2 + i] = MPC::deserialize_bytes(std::get<0>(coords_c));
      coordinates[batch_size * 3 + i] = MPC::deserialize_bytes(std::get<1>(coords_c));
    }
    // Sends the x and y coordinates
    this->one_run<gfp>(coordinates);
  }

  void MPC::MPCClient::send_G1_point(TEG::DecryptionShare &point)
  {
    // Gets the coordinates of the point and normalizes it, if not already done.
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> coords = point.share.get_coordinates();
    // Converts the coordinates to gfp
    gfp x = MPC::deserialize_bytes(std::get<0>(coords));
    gfp y = MPC::deserialize_bytes(std::get<1>(coords));
    // Sends the x and y coordinates
    this->one_run<gfp>({x, y});
  }

  // Gets an additive share from MPC_1 and converts it to a BN for the RISS scheme
  BilinearGroup::BN MPC::MPCClient::get_share(int index)
  {
    octetStream os;
    os.Receive(client.sockets[index - 1]);
    gfp value;
    value.unpack(os);
    return conv_gfp_to_bn(value);
  }

  std::vector<uint32_t> MPC::MPCClient::get_shares_xor(int &batch_size)
  {
    std::vector<gfp> values = client.receive_outputs<gfp>(batch_size);
    std::vector<uint32_t> xor_shares;
    for (int i = 0; i < batch_size; i++)
    {
      xor_shares.push_back(conv_gfp_to_x_type(values[i]));
    };
    return xor_shares;
  }

  std::vector<BilinearGroup::BN> MPC::MPCClient::get_shares(uint8_t &index, int &batch_size)
  {
    std::vector<BilinearGroup::BN> values(batch_size);
    std::vector<gfp> val = this->client.receive_outputs<gfp>(batch_size);
    for (int i = 0; i < batch_size; i++)
    {
      values[i] = conv_gfp_to_bn(val[i]);
    }
    return values;
  }
} // namespace MPC
