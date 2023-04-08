
import numpy as np
import random
from itertools import combinations
from Params import params_80,magic

def hammingdistance(a, b):
    count = 0
    for i in range(len(a)):
        if a[i]==b[i]:
            count = count + 1
    return count


def bc_check(bc_with_error,P,max_tolerant):
    index = list(range(len((bc_with_error))))
    # check whether there exits bc_p satisfies d(bc_p,bc_prime) < max_tolerant (i.e., n - r)

    bc_string = magic(bc_with_error)
    np.random.seed(bc_string % (2 ** 32 - 1))
    bc_value = np.random.randint(1, 1e6)
    bc_G = pow(params_80.g, bc_value, params_80.p)
    if  bc_G == P:
        return True
    else:
        for distance_enum in range(1, max_tolerant + 1):
            chosen_index = list(combinations(index, distance_enum))
            #print(chosen_index)
            #random.shuffle(chosen_index) # It seems to be feasible, but will influence the performance
            for i in range(len(chosen_index)):
                bc_enum = bc_with_error.copy()
                for j in range(distance_enum):
                    bc_enum[chosen_index[i][j]] = bc_enum[chosen_index[i][j]]^1
                bc_enum_string = magic(bc_enum)
                np.random.seed(bc_enum_string % (2 ** 32 - 1))
                bc_enum_value = np.random.randint(1, 1e6)
                if pow(params_80.g, bc_enum_value, params_80.p) == P:
                    return True
    return False

if __name__ == '__main__':
    n = 8
    t = 5
    max_tolerant = 3
    bc = np.random.randint(0, 2, n)
    bc_string = magic(bc)
    np.random.seed(bc_string % (2 ** 32 - 1))
    bc_value = np.random.randint(1, 1e6)
    P = pow(params_80.g, bc_value, params_80.p)
    #print(index)
    errors = 3  # error is logn, where n is the length of the biometric characteristics
    bc_with_error = bc.copy()
    for i in range(errors):
        bc_with_error[len(bc_with_error) - i - 1] = (bc_with_error[len(bc_with_error) - i - 1] + 1) % 2
    #print(chosen_index)

    print(bc_check(bc_with_error,P,max_tolerant))
