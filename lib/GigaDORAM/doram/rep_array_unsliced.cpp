#include "rep_array_unsliced.h"
namespace emp
{
    template <>
    template <>
    void rep_array_unsliced<block>::copy_one(uint dst_index, rep_array_unsliced<block> &src, uint src_index)
    {
        assert(src_index < src.length_Ts());
        assert(dst_index < length_Ts());
        prev[dst_index] = (src.prev)[src_index];
        next[dst_index] = (src.next)[src_index];
    }

    template <>
    void rep_array_unsliced<block>::f()
    {
        return;
    }

    template <>
    template <typename IO_t>
    inline void rep_array_unsliced<block>::io_send_next(IO_t *next_io)
    {
        next_io->send_block(next, length_Ts());
    }

    template <>
    template <typename IO_t>
    inline void rep_array_unsliced<block>::io_recv_prev(IO_t *prev_io)
    {
        prev_io->recv_block(prev, length_Ts());
    }
}