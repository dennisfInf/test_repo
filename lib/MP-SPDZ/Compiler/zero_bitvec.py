"""Code generated by AI"""
from concurrent.futures import ThreadPoolExecutor
from Compiler.types import *
from Compiler.library import *

def check_if_non_zerovec(scalars,bit_position,num_threads=4):
 # Split the 2D array into chunks for parallel processing
    result = MemValue(cint(1))  # Start with True (1)
    @for_range(len(scalars))
    def _(i):
        result.write(result.read()+scalars[i][bit_position]) 
    @if_e(result.read()>0)
    def _():
        return cint(1)
    @else_
    def _():
        return cint(0)

