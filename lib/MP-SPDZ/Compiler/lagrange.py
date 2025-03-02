from Compiler.types import *
from Compiler.library import *

lagrange1_2 = cint(2)
lagrange2_2 = cint(5541245505022739011583672869577435255026888277144126952448297309161979278754528049907713682488818304329661351460876)
lagrange2_3 = cint(3)
lagrange3_3 = cint(5541245505022739011583672869577435255026888277144126952448297309161979278754528049907713682488818304329661351460875)


def get_bits_lsb_first(value, bit_length=None):
    """Returns an array of bits (LSB first) of the given integer."""
    if bit_length is None:
        bit_length = value.bit_length() or 1  # Ensure at least one bit is considered
    
    return [(value >> i) & 1 for i in range(bit_length)]





def get_lagrange(t,n):
    X = cint.Tensor([2,t+1,382])
    X[0][0] = get_bits_lsb_first(lagrange1_2,382)
    X[0][1] = get_bits_lsb_first(lagrange2_2,382)
    X[1][0] = get_bits_lsb_first(lagrange2_3,382)
    X[1][1] = get_bits_lsb_first(lagrange3_3,382)
    return X