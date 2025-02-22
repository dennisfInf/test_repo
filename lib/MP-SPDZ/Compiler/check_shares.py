from Compiler.types import *
from Compiler.library import *

# start = 1 end = t+2 
def compute_lagrange_coeffs(n,x_coord, start, end):
    coeffs = regint.Tensor([end-start+1,380])
    counter = 0
    for player_index in range(start,end):
        print("execute")
        numerator = cint(1)
        denominator = cint(1)
        for j in range(1,n+1): 
            if (j == player_index):
                continue
            j_bn = cint(j)
            numerator = numerator * (j_bn - x_coord)
            denominator = denominator * (j_bn - player_index)
        coefficient = numerator.field_div(denominator)
        coeffs[counter] = coefficient.bit_decompose()
        counter = counter +1

    return coeffs

def compute_lagrange_coeffs_no_decompose(n,x_coord, start, end):
    coeffs = regint.Array(end-start+1)
    counter = 0
    for player_index in range(start,end):
        print("execute")
        numerator = cint(1)
        denominator = cint(1)
        for j in range(1,n+1): 
            if (j == player_index):
                continue
            j_bn = cint(j)
            numerator = numerator * (j_bn - x_coord)
            denominator = denominator * (j_bn - player_index)
        coeffs[counter] = numerator.field_div(denominator)
        counter = counter +1

    return coeffs

def test_lagrange_coeffs(n,x_coord,start,end):
    coeffs = regint.Tensor([end-start+1,380])
    counter = 0
    for player_index in range(start,end):
        print("execute")
        numerator = cint(1)
        denominator = cint(1)
        for j in range(1,n+1): 
            if (j == player_index):
                continue
            j_bn = cint(j)
            numerator = numerator * (j_bn - x_coord)
            denominator = denominator * (j_bn - player_index)
        coefficient = numerator.field_div(denominator)
        print_ln("coef %s \n", coefficient.reveal())
        test = coefficient.bit_decompose()
        for x in test:
            print_ln(" %s ", x.reveal())

        coeffs[counter] = coefficient.bit_decompose()
        counter = counter +1

    return coeffs


# sollte man noch vektorisieren
def reshare(n,t,secrets):
    points = sint.Tensor([n,len(secrets)])
    coeffs = sint.Tensor([len(secrets),t])
    for j in range(len(secrets)):
        for i in range(t):
            coeffs[j][i] = sint.get_random()
    print(len(secrets))
    print(n)
    print(len(coeffs))
    for player in range(n):
        for i in range(len(secrets)):
            player_share = secrets[i]
            for j in range(t):
                player_share += coeffs[i][j] ** j
            points[player][i] = player_share

    return points


def interpolate(points,coeffs):
    sum = sint(0)
    for i in range(len(coeffs)):
        sum += (points[i] * coeffs[i])

    return sum