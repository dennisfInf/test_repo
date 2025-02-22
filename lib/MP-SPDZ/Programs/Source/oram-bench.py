from path_oram import OptimalORAM
from Compiler.library import print_ln, if_, do_while,crash
from Compiler.types import MemValue

dim_1 = 32768
dim_2 = 6
LOG_BOOK_SIZE = 59
oram = OptimalORAM(size=dim_1, entry_size=[32]*dim_2*LOG_BOOK_SIZE, init_rounds=0, value_type=sint)

start_timer(10)
import util

entries = list(oram[50])
print_ln('%s', util.reveal(entries)) 
start_timer(11)
unwritten = MemValue(sintbit(1))
print_ln("called")
b = MemValue(sintbit(0))
x = range(1, LOG_BOOK_SIZE)
msg = [1000001, 1000002, 1000003, 1000004, 1000005, 1000006]

def insert_message(first_entry,unwritten,msg,b):

    print_ln('%s', util.reveal(entries[first_entry])) 
    b.write(unwritten & (entries[first_entry].equal(sint(0))))
    print_ln("b: %s", b.reveal())
    unwritten.write(unwritten ^ (b))
    c = sint(1-b)
    d = sint(b)
    entries[first_entry] = c * entries[first_entry] + d * msg[0]
    entries[first_entry+1] = c * entries[first_entry+1] + d * msg[1]
    entries[first_entry+2] = c * entries[first_entry+2] + d * msg[2]
    entries[first_entry+3] = c * entries[first_entry+3] + d * msg[3]
    entries[first_entry+4] = c * entries[first_entry+4] + d * msg[4]
    entries[first_entry+5] = c * entries[first_entry+5] + d * msg[5]

insert_message(0,unwritten,msg,b)
for i in x:
    insert_message(i*dim_2,unwritten,msg,b)

new_entry = tuple(entries)
stop_timer(11)
oram[50] = new_entry
print_ln('%s', util.reveal(oram[50])) 

stop_timer(10)


