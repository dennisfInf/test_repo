#pragma once

#include "emp-tool/emp-tool.h"
#include "rep_net_io_channel.h"
#include <thread>
#include <map>

using namespace std;

namespace emp
{

  class AbandonIO : public IOChannel<AbandonIO>
  {
  public:
    void flush()
    {
    }

    void send_data_internal(const void *data, int len)
    {
    }

    void recv_data_internal(void *data, int len)
    {
    }
  };

  class BristolFashion_array;

  // party conventions:
  // 1: Party 1
  // 2: Party 2
  // 3: Party 3
  extern int party;
  extern std::string webserver_address;
  extern uint16_t webserver_port;
  extern uint NUM_THREADS;
  extern uint elems_length;

  // Each of the thread_unsafe:: resources is an array of length num_threads
  // which has to be initialized in main. The 0th element is the default
  // for code that will never run in a thread. Code that runs in threads
  // should look up its thread's assigned resources.
  // The ith thread_unsafe::prev resource is assumed to be connected to
  // the previous party's ith thread_unsafe::next resource.

  class SHRepArray;
  class MalRepArray;

  extern PRG **prev_prgs;
  extern PRG **next_prgs;
  extern PRG **private_prgs;
  extern PRG **shared_prgs;

  extern RepNetIO **prev_ios;
  extern RepNetIO **next_ios;
  extern SHRepArray **rep_execs;

  namespace thread_unsafe
  {

    extern PRG *prev_prg;
    extern PRG *next_prg;
    // does private_prg really need to be thread_unsafe?
    extern PRG *private_prg;
    extern PRG *shared_prg;

    extern RepNetIO *prev_io;
    extern RepNetIO *next_io;
    extern SHRepArray *rep_exec;

  }

  // TIMING
  extern fstream timing_file;
  extern fstream special_debug_file;

  // ignore setup
  extern double time_total;
  extern vector<double> time_total_builds;
  extern double time_total_build_prf;
  extern double time_total_batcher;
  extern double time_total_deletes;
  extern double time_total_queries;
  extern double time_total_query_prf;
  extern double time_total_query_stupid;
  extern double time_total_shuffles;
  extern double time_total_cht_build;
  extern double time_total_transpose;

  // The following timings are not thread safe and commented out for now
  /*
  double time_total_mand = 0;
  double time_compute_start = 0;
  double time_compute_finish = 0;
  double time_main_loop = 0;
  */

  // double time_total_network = 0; // defined in rep_net_io to avoid include problem, can still be accessed globaly

  extern double time_doram_constructor; //? what is this for?

  typedef unsigned long long ull;

  typedef uint32_t x_type;
  typedef uint64_t y_type;

  extern BristolFashion_array *xy_if_xs_equal_circuit;
  extern BristolFashion_array *cht_lookup_circuit_file;
  extern BristolFashion_array *prf_circuit;
  extern BristolFashion_array *replace_if_dummy_circuit_file[32];
  extern BristolFashion_array *dummy_check_circuit_file[32];
  extern BristolFashion_array *compare_swap_circuit_file;

} // namespace emp
