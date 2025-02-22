from Compiler.types import *
from Compiler.library import *

def interpolate_shares(shares,t,coeffs):
    @for_range_opt_multithread(6, len(shares))
    def f(i):
        shares[i] = shares[i] * coeffs[i]
    result = []
    @for_range_opt_multithread(6, len(shares[0]))
    def f(i):
        @map_sum_opt(1, len(shares), [sint])
        def summer(j):
            return shares[j][i]
        result.append(summer())
    return result


# start = 1 end = t+2 
def compute_lagrange_coeffs(n,x_coord, start, end):
    coeffs = []
    for player_index in range(start,end):

        numerator = regint(1)
        denominator = regint(1)
        for j in range(1,n+1): 
            if (j == player_index):
                continue
            j_bn = regint(j)
            numerator = numerator * (j_bn - x_coord)
            denominator = denominator * (j_bn - player_index)
        if (denominator == regint(0)):
            print("denominator is zero (duplicate shares provided)")
            exit(1)
        coeffs.append(numerator.field_div(denominator))

    return coeffs