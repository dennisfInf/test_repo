from Compiler.types import *
from Compiler.library import *

# start = 1 end = t+2 
def compute_lagrange_coeffs(n,x_coord, start, end):
    coeffs = cint.Tensor([end-start+1,382])
    counter = 0
    for player_index in range(start,end+1):
        numerator = cint(1)
        denominator = cint(1)
        for j in range(start,end+1): 
            if (j == player_index):
                continue
            j_bn = cint(j)
            numerator = numerator * ( x_coord - j_bn)
            denominator = denominator * (player_index - j_bn)
        coefficient = numerator.field_div(denominator)
        print_ln("coeff: %s",coefficient)
        coeffs[counter] = get_bits_lsb_first(coefficient,382)
        counter = counter +1


    return coeffs

def get_bits_lsb_first(value, bit_length=None):
    """Returns an array of bits (LSB first) of the given integer."""
    if bit_length is None:
        bit_length = value.bit_length() or 1  # Ensure at least one bit is considered
    
    return [(value >> i) & 1 for i in range(bit_length)]





def lagrange_coefficient_secret_sharing(i, threshold):
    """
    Computes the Lagrange coefficient for a given player i in Shamir's Secret Sharing.
    The coefficient is evaluated at x = 0.

    :param i: The player's index (1-based)
    :param total_players: The total number of players (n)
    :return: The Lagrange coefficient λ_i used for reconstructing the secret
    """
    numerator = cint(1)
    denominator = cint(1)

    for j in range(1, threshold + 1):  # Players are indexed from 1 to n
        if j != i:
            numerator *= (0 - cint(j))  # Evaluating at x = 0
            denominator *= (cint(i) - cint(j))

    print_ln("denominator %s", denominator)
    print_ln("numerator %s", numerator)

    return numerator.field_div(denominator)  # λ_i for player i


def compute_lagrange_coeffs_no_decompose(n,x_coord, start, end):
    coeffs = cint.Array(end-start+1)
    counter = 0
    for player_index in range(start,end+1):
        numerator = cint(1)
        denominator = cint(1)
        for j in range(start,end+1): 
            if (j == player_index):
                continue
            j_bn = cint(j)
            numerator = numerator * (x_coord - j_bn )
            denominator = denominator * (player_index- j_bn)
        coeffs[counter] = numerator.field_div(denominator)
        counter = counter +1
    print_ln("coeffs no decompose \n \n")

    for x in coeffs:
        print_ln(" %s ", x.reveal())

    return coeffs

def test_lagrange_coeffs(n,x_coord,start,end):
    coeffs = cint.Tensor([end-start+1,382])
    counter = 0
    for player_index in range(start,end):
        numerator = cint(1)
        denominator = cint(1)
        for j in range(start,end+1): 
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

    for player in range(n):
        for i in range(len(secrets)):
            player_share = secrets[i]
            for j in range(t):
                player_share += coeffs[i][j]*((player+1)** (j+1))
            points[player][i] = player_share

    return points


def interpolate(points,lagrange):
    secrets = sint(0)
    for i in range(len(lagrange)):
        secrets += (points[i] * lagrange[i])

    return secrets


    # sollte man noch vektorisieren
#def reshare(n,t,secrets):
 #   points = sint.Tensor([len(secrets),n])
  #  coeffs = sint.Tensor([len(secrets),t])
   # for j in range(len(secrets)):
 #       for i in range(t):
  #          coeffs[j][i] = sint.get_random()
  #  print_ln("len sec %s", len(secrets))
  #  print_ln("n: %s" ,n)
  #  print_ln("len coeffs: %s" , len(coeffs))
  #  print_ln("len coeffs: %s" , coeffs.reveal_nested())
   # players = regint.Array(n)
    # players starting with index 1, since 0 is the secret
 #   for player in range(n):
  #      players[player] = player+1
    
   # for n
  #  for i in range(len(secrets)):
  #      player_share = secrets[i]
  #      for j in range(t):
  #          player_share += coeffs[i][j]*(players**(j+1))
  #      points[i]=player_share
  #  return points