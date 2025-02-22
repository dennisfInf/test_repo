from Compiler.types import *
from Compiler.mpc_math import sqrt      
from Compiler.GC.types import sbit, sbitvec
from Compiler.program import *

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


def norm_point(X,Z):
    return X.field_div(Z*Z)
