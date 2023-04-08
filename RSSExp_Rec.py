#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from polynomials import mod_inverse
from shamir_secret_sharing import secret_int_to_points, points_to_secret_int
from Params import params_80
import random
from itertools import combinations
from random import shuffle
max_iteration = 1000000000000000000 # O(nlogn) is enough for the implementation
def RSSExp_Rec(x, points, p,q):
    # break the points up into lists of x and y values
    x_values, y_values = zip(*points)

    # initialize f(x) and begin the calculation:  f(x) = Mul(y_i^l_i(x)) for the RSSExp
    f_x = 1
    for i in range(len(points)):
        # evaluate the lagrange basis polynomial l_i(x)
        numerator, denominator = 1, 1
        for j in range(len(points)):
            # don't compute a polynomial fraction if i equals j
            if i == j:
                continue
            # compute a fraction & update the existing numerator + denominator
            numerator = (numerator * (x - x_values[j])) % q
            denominator = (denominator * (x_values[i] - x_values[j])) % q
        # get the polynomial from the numerator + denominator mod inverse
        lagrange_polynomial = numerator * mod_inverse(denominator, q)
        # multiply the current y & the evaluated polynomial & add it to f(x)
        f_x = ( f_x * pow(y_values[i] , lagrange_polynomial , p)) % p
    return f_x

def Rec(points, t, p, q):
    iteration = max_iteration  # O(nlogn) is enough for the implementation
    for i in range(iteration):  # repeat chosen random subset
        point_t = random.sample(points, t)
        # print(point_t)
        hold_equation_number = 0
        for j in range(len(points)):
            if RSSExp_Rec(points[j][0], point_t, p, q) == points[j][1]:
                hold_equation_number = hold_equation_number + 1
        # print(hold_equation_number)
        if hold_equation_number > t:
            output = RSSExp_Rec(0, point_t, p, q)
            return output

if __name__ == '__main__':
    #test the function RSSExp_Rec   # n = 64, t = 16, error = 6 256/64/8   32/8/5  128/
    secret = 2023
    n = 64
    t = 16
    a = secret_int_to_points(secret, t, n, prime=params_80.q)   # Share function
    REC = points_to_secret_int(a[0:5],prime=params_80.q) # Recon function
    # print(REC)
    errors = 5 # error is logn, where n is the length of the biometric characteristics
    for i in range(errors):
        a[i] = (a[i][0], 5)
    aa = [(i+1,pow(params_80.g,a[i][1],params_80.p)) for i in range(len(a))] # generate g^{a_i}
    #print(aa)
    recovery = RSSExp_Rec(0,aa,params_80.p,params_80.q)

    output = Rec(aa, t, params_80.p, params_80.q)
    print(pow(params_80.g,secret,params_80.p) == output) # test whether g^a == Rec(g^{a_i})

    print(pow(params_80.g,secret,params_80.p))

    print(output)