#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import numpy as np
from Crypto.Random.random import randint
import random
from oblivious_transfer import OT_Sender, OT_Receiver
from AES_cs import PrpCrypt
from shamir_secret_sharing import secret_int_to_points
from RSSExp_Rec import Rec
from bctest import bc_check
from Params import params_80,magic
import hashlib
from polynomials import mod_inverse
import json
from time import time

if __name__ == '__main__':
    n = 32 #The length of biometric characteristics   # n=24,t=10,error=3,max_tolerant=5
    t = 8 #threshold
    max_tolerant = 5 # max tolerance of errors
    #Set up Group G
    g = params_80.g
    q = params_80.q
    p = params_80.p # prime = 1024 bit
    # bc and pw
    pw = "password"
    bc = np.random.randint(0, 2, n)

    ##########Registration##########
    k = randint(1, q-1) #secret k
    v = randint(1, q-1) #secret v

    K = pow(g,k,p)
    bc_string = magic(bc)
    np.random.seed(bc_string %(2 ** 32 - 1))
    bc_value = np.random.randint(1, 1e6)
    P = pow(g,bc_value,p)

    k_shares = secret_int_to_points(k, t, n,q)  #Secret sharing
    v_shares = secret_int_to_points(v, t, n,q)
    #print(k_shares)
    r = [randint(1,q-1) for i in range(n)] #Generate {a_0i, a_1i} that is stored in File
    sha256 = hashlib.sha256()# Generate H(pw), namely pw_hash_G in this code
    sha256.update(pw.encode("utf-8"))
    pw_hash_int = int(str(sha256.hexdigest()),16)
    pw_hash_G = pow(g,pw_hash_int,p)

    value0 = [] #{a_0i, a_1i}
    value1 = []
    for i in range(n):
        if(bc[i]==0):
            value0.append((pow(g, k_shares[i][1], p) * pow(pw_hash_G, v_shares[i][1], p) ) % p) #* pow(2222, v_shares[i][1], p)
            value1.append(pow(g,r[i],p))
        else:
            value0.append(pow(g,r[i],p))
            value1.append((pow(g, k_shares[i][1], p) * pow(pw_hash_G, v_shares[i][1], p)) % p)

    ######### Authentication and Key Exchange ##########
    #On the user side ------------------
    errors = 2 # error is logn, where n is the length of the biometric characteristics
    bc_with_error = bc.copy() #the biometric characteristics with some errors
    index = random.sample(range(n),errors)
    #print(index)
    for i in range(errors):
        bc_with_error[index[i]] = (bc_with_error[index[i]] + 1) % 2
    time_user_round1_start = time()
    r1 = randint(1, q - 1)
    B = pow(pw_hash_G,r1,p)
    time_user_round1_end = time()
    #On the server side ------------------
    time_server_round1_start = time()
    k_prime = randint(1, q-1)
    secret_server = pow(K, k_prime, p)
    value0 = [pow(value0[i],k_prime,p) for i in range(n)] #compute A
    value1 = [pow(value1[i], k_prime, p) for i in range(n)]
    D = pow(B, v * k_prime, p)
    plaintext = {'value0' : value0,'value1':value1,'P':P}
    plaintext = json.dumps(plaintext)
    ciphertext = PrpCrypt(str(secret_server)).encrypt(plaintext) # compute the ciphertext, i.e., C

    secret_server = pow(K, k_prime, p)
    time_server_round1_end = time()
    random.seed(secret_server)  # compute PRG(secret)
    session_key_server = random.getrandbits(p.bit_length())

    #Execution of OT ------------------
    print('Start the execution of OT......')
    time_OT_server_start = []
    time_OT_server_end = []
    Server = OT_Sender(value0, value1)
    User = OT_Receiver(bc_with_error)

    time_OT_user_server_start = time()

    time_OT_server_start.append(time())
    A = Server.generate_A()
    time_OT_server_end.append(time())

    B = User.generate_B(A)

    time_OT_server_start.append(time())
    (e0, e1) = Server.generate_e0_e1(B)
    time_OT_server_end.append(time())

    a_bc_with_error = User.obtain_value(e0, e1)
    time_OT_user_server_end = time()

    a_bc_with_error_points = [(i+1,a_bc_with_error[i]) for i in range(n)]
    # print((pow(g, k_shares[2][1], p) * pow(pw_hash_G, k_shares[2][1], p)) % p) #test whether OT succeeds

    #On the user side ------------------
    print('Start the recovery of the secret......')
    time_user_rec_start = time()
    recovery = Rec(a_bc_with_error_points, t, p, q)
    time_user_rec_end = time()
    # print((pow(g, k, p) * pow(pw_hash_G, v, p)) % p == recovery) # test whether g^k * H(pw)^v = Rec({a_bc_i}_{i=1,2,...,n})

    time_user_round2_start = time()
    D = pow(D, mod_inverse(r1,q),p)
    secret_user = recovery * mod_inverse(D, p) % p

    Dec_plaintext = PrpCrypt(str(secret_user)).decrypt(ciphertext)
    Dec_plaintext = json.loads(Dec_plaintext)
    time_user_round2_end = time()
    #print(Dec_plaintext['P'])

    print('Start checking (1) and (2)......')
    time_user_check_start = time()
    # Checking (1)
    check1 = True
    for i in range(n):
        value = Dec_plaintext['value0'][i] if bc_with_error[i]==0 else Dec_plaintext['value1'][i]
        if(a_bc_with_error[i] != value):
            check1 = False
            break
    print('Checking (1) succeeds!') if check1 else print('Checking (1) fails!')

    #Checking (2)
    check2 = bc_check(bc_with_error, P, max_tolerant)
    print('Checking (2) succeeds!') if check2 else print('Checking (2) fails!')
    time_user_check_end = time()

    random.seed(secret_user) # compute PRG(secret)
    session_key_user = random.getrandbits(p.bit_length())

    # test whther K_u = K_s
    print(session_key_server == session_key_user)
    #print(session_key_user.bit_length())

    # print(secret==pow(g,k*k_prime,p)) #test whether the secret of the server is identical to that of the user

    ####the evaluation of computation costs on the user and the server side #######

    time_user_round1 = time_user_round1_end - time_user_round1_start
    #print("The time of user in round 1: " + str(time_user_round1) + 's') # default is 0.0001915 s. For more details, please see simple_test

    time_user_round2 = time_user_round2_end - time_user_round2_start # decryption +computation of K = K*D^{-1}
    #print("The time of user in round 2: " + str(time_user_round2) + 's')  # default is 0.0001915 s. For more details, please see simple_test

    time_server_round1 = time_server_round1_end - time_server_round1_start
    #print("The time of server in round 1: " + str(time_server_round1) + 's')

    time_OT_server = sum(time_OT_server_end) - sum(time_OT_server_start)
    print("The time of server during the execution of OT: " + str(time_OT_server)+ 's')
    time_OT_user = time_OT_user_server_end - time_OT_user_server_start - time_OT_server
    print("The time of user during the execution of OT: " + str(time_OT_user) + 's')

    time_user_rec = time_user_rec_end - time_user_rec_start
    print("The time of user for recovery: " + str(time_user_rec) + 's')

    time_user_check = time_user_check_end - time_user_check_start
    print("The time of user for checking: " + str(time_user_check) + 's')

    time_user_total = time_user_round1 + time_user_round2 + time_OT_user + time_user_rec + time_user_check
    print('The computational costs of the user: ' + str(time_user_total))

    time_server_total = time_server_round1 + time_OT_server
    print('The computational costs of the server: ' + str(time_server_total))

