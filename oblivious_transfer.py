#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Ref: https://eprint.iacr.org/2015/267.pdf The Simplest Protocol for Oblivious Transfer

from Crypto.Random.random import randint
from gmpy2 import invert
import numpy as np

from AES_cs import PrpCrypt
from rfc_3526_groups import RFC_3526_GROUPS

class OT_Sender:
    def __init__(self, value0, value1, groupID=4):
        self.g = RFC_3526_GROUPS[groupID][0]
        self.p = RFC_3526_GROUPS[groupID][1]
        self.value0 = value0
        self.value1 = value1
        self.a = randint(1, self.p - 1)

    def get_params(self):
        return self.g, self.p

    def generate_A(self):
        A = pow(self.g, self.a, self.p)
        self.A = A
        return A

    def generate_e0_e1(self, B):
        e0 = []
        e1 = []
        for i in range(len(self.value0)):
            k0_i = pow(B[i], self.a, self.p)
            k1_i = pow(B[i]*int(invert(self.A,self.p)), self.a, self.p)
            e0.append(PrpCrypt(str(k0_i)).encrypt(str(self.value0[i])))
            e1.append(PrpCrypt(str(k1_i)).encrypt(str(self.value1[i])))
        return (e0, e1)

class OT_Receiver:

    def __init__(self, selection_bit, groupID=4):
        self.g = RFC_3526_GROUPS[groupID][0]
        self.p = RFC_3526_GROUPS[groupID][1]
        self.selection_bit = selection_bit # c
        self.b = [randint(1,self.p - 1) for i in range(len(selection_bit))]

    def get_params(self):
        return self.g, self.p

    def generate_B(self, A):
        B = []
        kr = []
        for i in range(len(self.selection_bit)):
            if self.selection_bit[i] == 0:
                B.append(pow(self.g, self.b[i], self.p))
            else:
                B.append((A * pow(self.g, self.b[i], self.p)) % self.p)

            kr.append(pow(A, self.b[i], self.p))
        self.B = B
        self.kr = kr
        return B

    def obtain_value(self, e0, e1):
        value = []
        for i in range(len(self.selection_bit)):
            if self.selection_bit[i] == 0:
                cipher = e0[i]
            else:
                cipher = e1[i]
            value.append(int(PrpCrypt(str(self.kr[i])).decrypt(cipher)))
        return value

if __name__ == '__main__':
    n = 1000
    value0 = [randint(1,RFC_3526_GROUPS[4][1]) for i in range(n)]
    value1 = [randint(1,RFC_3526_GROUPS[4][1]) for i in range(n)]

    selection_bit = np.random.randint(0,2,n)
    print(value0)
    print(value1)
    print(selection_bit)

    Server = OT_Sender(value0,value1)
    User = OT_Receiver(selection_bit)
    A = Server.generate_A()
    B = User.generate_B(A)
    (e0,e1) = Server.generate_e0_e1(B)
    m = User.obtain_value(e0,e1)
    print(str(m[0:10]))