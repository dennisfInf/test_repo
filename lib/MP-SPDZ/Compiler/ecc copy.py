from Compiler.types import *
from Compiler.mpc_math import sqrt      
from Compiler.GC.types import sbit, sbitvec
from Compiler.program import *
from concurrent.futures import ThreadPoolExecutor
from Compiler.weighted_sum import *
from Compiler.zero_bitvec import *
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


def add_points_bernstein_vec(vec1,vec2,vec3)
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
    X = (regint(0),regint(0),regint(0))
    bit_length = cint(len(scalars))
    # Number of threads to use
    num_threads = 4
    @if_(check_if_non_zerovec(scalars,bit_length-1))
    def _():
        X = parallel_weighted_sum(points,scalars[len(scalars)-1],num_threads)
    @for_range_opt(bit_length-2,-1,-1)
    def _(i):
        point_doubling_alnr(*X)
        if(check_if_non_zerovec(scalars,i)):
            weighted_sum = parallel_weighted_sum(points,scalars[len(scalars)-1],num_threads)
            X = add_points_bernstein(*X,*weighted_sum)
    return X[0],X[1],X[2]


def norm_point(X,Z):
    return X.field_div(Z*Z)
