from Params import params_80
from time import time
from shamir_secret_sharing import secret_int_to_points
from random import  randint
from itertools import combinations
'''
number = randint(1,params_80.q)
a = time()
for i in range(100000):
    pow(params_80.g,number,params_80.p)
b = time()
print('Exp_G: '+ str((b-a)/100000)+ 's')

Exp_G = (b-a)/100000

number = randint(1,params_80.p)
a = time()
for i in range(100000):
    number*number % params_80.p
b = time()
print('Mul_G: '+ str((b-a)/100000)+ 's')

Mul_G = (b-a)/100000

number = randint(1,params_80.p)
a = time()
for i in range(100000):
    (number + number) % params_80.p
b = time()
print('Add_G: '+ str((b-a)/100000)+ 's')

Add_G = (b-a)/100000

number = randint(1,params_80.q)
a = time()
for i in range(100000):
    number*number % params_80.q
b = time()
print('Mul_Z_q: '+ str((b-a)/100000)+ 's')

Mul_Z_q = (b-a)/100000

number = randint(1,params_80.q)
a = time()
for i in range(100000):
    (number + number) % params_80.q
b = time()
print('Add_Z_q: '+ str((b-a)/100000)+ 's')

Add_Z_q = (b-a)/100000
'''
# cryptographic operation
Exp_G = 0.0006386164164543152
Mul_G = 2.5029945373535155e-06
Add_G = 2.8921842575073244e-07
Mul_Z_q = 3.091740608215332e-07
Add_Z_q = 1.1967897415161133e-07
n = 32
aa = (n*4+4)*Exp_G
print(aa)

# Computation costs of register # 改变t n = 64 128
#n = 64
n = 128
computation_server_regi = []
for t in range(0,24,4):
     computation_server_regi.append((3*n+3)*Exp_G+n*Mul_G+(2*n*t-2*n)*(Mul_Z_q + Add_Z_q))
print('server cost registeation: ' + str(computation_server_regi))

# Computation costs of register #改变n t = 8 16 24
#t = 12
#t = 24
t = 36
computation_server_regi = []
for n in range(16,112,16):
     computation_server_regi.append((3*n+3)*Exp_G+n*Mul_G+(2*n*t-2*n)*(Mul_Z_q + Add_Z_q))
print('server cost registeation2: ' + str(computation_server_regi))




# Storage costs
n = 128
G = 1024
Z_q = 160
storage_cost = []
for N in range(0,1200,200):
    storage_cost.append((N*(2*n+2)*G + N*Z_q)/8388608) #MB
print(storage_cost) #MB

'''
n = 128
t = 32

a2 = time()
for i in range(10000):
    secret_int_to_points(222, t, n, prime=params_80.q)
b2 = time()
print(str((b2-a2))+ 's')  # Share function
'''
index = list(range(4))
chosen_index = list(combinations(index, 2))
print(chosen_index)