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
def multi_exp_shamir_method(points,scalars,batch_size):
    X = sint.Tensor([3,batch_size])
    for i in range(3):
        X[i] = list([sint(1)]*batch_size)
    bit_length = len(scalars)
    # Number of threads to use
    print("type1: %s",type(X))
    num_threads = 4
    @if_(check_if_non_zerovec(scalars,bit_length-1))
    def _():
        nonlocal X
        X = sequential_weighted_sum(points,scalars,len(scalars)-1)
        print("type2: %s",type(X))
    @for_range_opt(bit_length-2,-1,-1)
    def _(i):
        nonlocal X
        X = point_doubling_alnr(X[0],X[1],X[2])
        print("type3: %s",type(X))
        @if_(check_if_non_zerovec(scalars,i))
        def _():
            nonlocal X
            weighted_sum = sequential_weighted_sum(points,scalars, i)
            X = add_points_bernstein(X[0],X[1],X[2],weighted_sum[0],weighted_sum[1],weighted_sum[2])
            print("type4: %s",type(X))
    print("type5: %s",type(X))

    return X


def norm_point(X,Z):
    return X.field_div(Z*Z)

def norm_point_with_y(X,Y,Z):
    Z2 = Z*Z
    Z3 = Z2*Z
    return X.field_div(Z2),Y.field_div(Z3)


def sequential_weighted_sum(values, scalars, position):
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
    total_sum = values[0]

    # Iterate over all values and scalars sequentially
    for j in range(1,len(values)):
        bit = scalars[j][position] != 0  # Check if the scalar is non-zero
        @if_(bit)
        def _():
            # Add the current value to the total sum using add_points_bernstein
            nonlocal total_sum
            total_sum = add_points_bernstein(
                total_sum[0],
                total_sum[1],
                total_sum[2],
                values[j][0],
                values[j][1],
                values[j][2]
            )

    # Return the final computed weighted sum
    return total_sum