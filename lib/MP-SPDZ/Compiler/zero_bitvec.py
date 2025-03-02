from concurrent.futures import ThreadPoolExecutor
from Compiler.types import *
from Compiler.library import *

def check_if_non_zerovec(scalars,bit_position):
 # Split the 2D array into chunks for parallel processing
    counter = MemValue(cint(0)) 
    isbit_zero = MemValue(regint(0))
    @do_while
    def _():
        isbit_zero.write(scalars[counter.read()][bit_position] == regint(1))
        counter.write(counter.read()+1)
        return 1-isbit_zero.read().bit_or(counter>=len(scalars)) 

    return isbit_zero.read(),(counter.read()-1)
    
    
