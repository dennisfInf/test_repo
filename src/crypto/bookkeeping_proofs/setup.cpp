#include "crypto/bookkeeping_proofs/setup.h"
#include "crypto/proofs/prelude.hpp"
#include "crypto/schemes/bls_sig/scheme.h"
#include <chrono>

// in prelude.hpp
//  static const char* SERIALIZATION_FILE = "CRS.txt";

namespace GS
{

using namespace std;
using namespace BilinearGroup;
namespace zkp
{
/* Build and fill the precomputation tables */
void build_tables(CRS &crs)
{
  crs.v1(0, 0).precompute();
  crs.u1(0, 0).precompute();
  crs.u1(1, 0).precompute();
  crs.H.precompute();
  crs.bls_pk.precompute();
  crs.v2(0, 0).precompute();
  crs.u2(0, 0).precompute();
  crs.u2(0, 1).precompute();
}

// generate CRS without serialization
CRS generate_crs()
{
  CRS crs;
  {
    auto ro = BN::rand();
    auto xi = BN::rand();
    crs.v1 = {xi * G1::get_gen(), G1::get_gen()};
    crs.w1 = crs.v1 * ro;
    G1Vec u_temp = {G1::get_infty(), G1::get_gen()};
    crs.u1 = crs.w1 + u_temp;
    crs.H = G1::rand();
    BLS::Signatures sigs = BLS::Signatures();
    sigs.generate_keys();
    crs.bls_pk = sigs.get_public_key();
    BN::mod_inverse(crs.xi, xi, G1::get_group_order());
  }
  {
    auto sig = BN::rand();
    auto psi = BN::rand();
    crs.v2 = {psi * G2::get_gen(), G2::get_gen()};
    crs.w2 = crs.v2 * sig;
    G2Vec u_temp = {G2::get_infty(), G2::get_gen()};
    crs.u2 = crs.w2 + u_temp;

    BN::mod_inverse(crs.psi, psi, G2::get_group_order());
  }
  return crs;
}

// setup of CRS without (de-)serialization
std::unique_ptr<CRS> setup_crs()
{
  auto crs = std::make_unique<CRS>(generate_crs());

  return crs;
}
} // namespace zkp

} // namespace GS
