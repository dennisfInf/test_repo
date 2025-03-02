from Compiler.types import *
from Compiler.library import *
from Compiler.mpc_math import sqrt      
from Compiler.GC.types import sbit, sbitvec
from Compiler.program import *
from concurrent.futures import ThreadPoolExecutor
from Compiler.zero_bitvec import *
import os
num_cores = os.cpu_count()
def derive_Y_and_Z_from_X(X,p,data_type):
    # Constants for BLS12-381
    a = -3
    b = 4

    # Calculate Y
    Y = X**3 + b

    # Set Z to 1
    Z = data_type(1)

    return Y, Z

# does not check for point at infinity here, because no party should have it as a secret share
# also does not check if point is on the curve, because we assume that the parties are honest
# Points are distinct with overwhelming probability, thus we do not check for equality
def add_points(X1, Y1, Z1, X2, Y2, Z2):
    T1 = X1 * X2
    T2 = Y1 * Y2
    T3 = Z1 * Z2
    T4 = (X1 + Y1) * (X2 + Y2) - T1 - T2
    T5 = (Z1 + Z2) ** 2 - T3 - T2
    X3 = T4 * T5
    Y3 = T2 * (T5 * T3 - 2 * T1)
    Z3 = (T1 * T2 - T4 * T3) * T3
    return [X3, Y3, Z3]

def add_points_affine(x1, y1, x2, y2):
        # Regular point addition
    lam = (y2 - y1) / (x2 - x1)

    x3 = lam * lam - x1 - x2
    y3 = lam * (x1 - x3) - y1

    return x3, y3
def add_points_bernstein_lange_for_aff(X1,Y1,X2,Y2):
      H = X2-X1
      HH = H2
      I = 4*HH
      J = H*I
      r = 2*(Y2-Y1)
      V = X1*I
      X3 = r2-J-2*V
      Y3 = r*(V-X3)-2*Y1*J
      Z3 = 2*H
      return X3,Y3,Z3


def add_points_bernstein_vec(vec1,vec2,vec3):
      vec3**2
      Z1Z1 = Z1**2
      Z2Z2 = Z2**2
      U1 = X1*Z2Z2
      U2 = X2*Z1Z1
      S1 = Y1*Z2*Z2Z2
      S2 = Y2*Z1*Z1Z1
      H = U2-U1
      I = (2*H)**2
      J = H*I
      r = 2*(S2-S1)
      V = U1*I
      X3 = r**2-J-2*V
      Y3 = r*(V-X3)-2*S1*J
      Z3 = ((Z1+Z2)**2-Z1Z1-Z2Z2)*H
      return X3,Y3,Z3


def add_points_bernstein(X1,Y1,Z1,X2,Y2,Z2):
      Z1Z1 = Z1**2
      Z2Z2 = Z2**2
      U1 = X1*Z2Z2
      U2 = X2*Z1Z1
      S1 = Y1*Z2*Z2Z2
      S2 = Y2*Z1*Z1Z1
      H = U2-U1
      I = (2*H)**2
      J = H*I
      r = 2*(S2-S1)
      V = U1*I
      X3 = r**2-J-2*V
      Y3 = r*(V-X3)-2*S1*J
      Z3 = ((Z1+Z2)**2-Z1Z1-Z2Z2)*H
      return X3,Y3,Z3

def point_doubling_alnr(X1,Y1,Z1):
      A = X1**2
      B = Y1**2
      ZZ = Z1**2
      C = B**2
      D = 2*((X1+B)**2-A-C)
      E = 3*A
      F = E**2
      X3 = F-2*D
      Y3 = E*(D-X3)-8*C
      Z3 = (Y1+Z1)**2-B-ZZ
      return X3,Y3,Z3

#scalars are two dimensional vecs, where the first dimension are the variables and the second dimension the bits of the variables
def multi_exp_shamir_method(points,scalars):
    bit_length = len(scalars[0])
    iterator = MemValue(cint(bit_length))

    # Loop until there is a non zero scalar vector at bit position iterator
    # scalar vectors only containing zeros can be ignored and this is why it's done here for a performance boost
    scalar_index  = MemValue(regint(0))
    @do_while
    def _():
        iterator.write(iterator.read()-1)
        check,index = check_if_non_zerovec(scalars,iterator.read())
        scalar_index.write(index)
        return 1-(check).bit_or(iterator.read() <= cint(0))
    X = sint.Tensor([3,len(points[0][0])])

    #Should there not a single bit vector over all scalars be found that is non zero, then the point at infinity is returned
    @if_e(iterator.read()<0)
    def _():
        for i in range(3):
            X[i] = list([sint(1)]*len(points[0][0]))
        print_ln("whole scalar vec only contained zeros: %s" , X[0].reveal())

    @else_
    def _():
        # Did this outside the loop of the orginal shamir method, since point doubling the point at infinity is equal to the point at infinity.
        # would result in unneccessary computation
        X[0],X[1],X[2] = sequential_weighted_sum(points,scalars,iterator.read(),scalar_index.read())
        # result should not equal to point at inifnity now, since we made sure that at positon iterator, where is at least one bit that is a one in the bit vec
        l = iterator.read() -1
        @for_range_opt(l,regint(-1),regint(-1))
        def _(i):
# For whatever reason this loop runs until i=-2, seems like a bug of mpspdz
            @if_(i>=0)
            def _():
                X[0],X[1],X[2] = point_doubling_alnr(X[0],X[1],X[2])
                check,index = check_if_non_zerovec(scalars,i)
                scalar_index.write(index)
                @if_(check==cint(1))
                def _():
                    weighted_sum = sequential_weighted_sum(points,scalars, i,scalar_index.read())
                    X[0],X[1],X[2] = add_points_bernstein(X[0],X[1],X[2],weighted_sum[0],weighted_sum[1],weighted_sum[2])


    return X


def norm_point(X,Z):
    return X.field_div(Z*Z)

def norm_point_with_y(X,Y,Z):
    Z2 = Z*Z
    Z3 = Z2*Z
    result = sint.Tensor([2,len(X)])
    for i in range(len(X)):
        result[0][i] = X[i].field_div(Z2[i])
        result[1][i] = Y[i].field_div(Z3[i])
    return result


def sequential_weighted_sum(values, scalars, position,scalar_index):
    """
    Computes the sum of P * i for each P in values and corresponding i in scalars.
    Skips multiplication when i == 0. Executes sequentially.

    :param values: List of tuples (P values with 3 components each).
    :param scalars: List of scalar values (corresponding to each P).
    :param position: Position in scalars to check.
    :return: The computed weighted sum as a tuple of three components.
    """
    # Ensure values and scalars have the same length
    if len(values) != len(scalars):
        raise ValueError("The lengths of values and scalars must be the same.", len(values), len(scalars))

    # Initialize the total sum as a tuple of secure values    
    X = sint.Tensor([3,len(values[0][0])])

        # else assign the first point where the first bit is 1 to the sum instead adding it with the point at infinity


    X[0] = values[scalar_index][0]
    X[1] = values[scalar_index][1]
    X[2] = values[scalar_index][2]
    # Iterate over all values and scalars sequentially
    @for_range(scalar_index+1,len(values))
    def _(j):
        bit = scalars[j][position] != 0  # Check if the scalar is non-zero
        @if_(bit)
        def _():
            print_ln("scalar %s at position %s is added", j,position)
            # Add the current value to the total sum using add_points_bernstein
            X[0],X[1],X[2] = add_points_bernstein(
                X[0],
                X[1],
                X[2],
                values[j][0],
                values[j][1],
                values[j][2]
            )
        # Doing the addition with the weighted sum in this method. This avoids, that the result of the weighted sum is the point at infinity, which is not handled
        # by the addition formula

    return X


def test_mul_exp(values, scalars):
    for i in range(len(scalars[0])):
        point_doubling_alnr(X[0],X[1],X[2])





    # Return the final computed weighted sum
