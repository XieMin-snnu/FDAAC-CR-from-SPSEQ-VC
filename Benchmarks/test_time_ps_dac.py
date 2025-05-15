import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bplib.bp import BpGroup
from core.ps_dac import DAC
from core.util import *
import timeit
import time


message1_str = ['living situation = with family',
 'gender = male',
 'car ownership = yes',
 'pet ownership = dog',
 'favorite color = blue',
 'name = Charlie',
 'hair color = blonde',
 'age = 30',
 'height = 182',
 'marital status = married',
 'company = Company B',
 "education = Bachelor's",
 'driver license type = B',
 'weight = 70',
 'favorite food = pizza',
 'salary range = >150k',
 'profession = engineer',
 'eye color = gray',
 'hobbies = reading',
 'nationality = Canadian'] + ['gender = other',
 'hair color = blonde',
 'weight = 70',
 'hobbies = cooking',
 'favorite color = purple',
 "education = Master's",
 'nationality = Canadian',
 'living situation = with family',
 'company = Company C',
 'height = 194',
 'name = Diana',
 'age = 35',
 'salary range = 50k-100k',
 'car ownership = yes',
 'pet ownership = none',
 'driver license type = B',
 'marital status = married',
 'favorite food = pasta',
 'profession = lawyer',
 'eye color = green'] + ["driver license type = B","genther = male"]
#all_indics = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41]
all_indics = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]
## subset of each message set
SubList1_str = ['living situation = with family',
 'gender = male',
 'car ownership = yes',
 'pet ownership = dog',
 'favorite color = blue',
 'name = Charlie',
 'hair color = blonde',
 'age = 30',
 'height = 182',
 'marital status = married',
 'company = Company B',
 "education = Bachelor's",
 'driver license type = B',
 'weight = 70',
 'favorite food = pizza',
 'salary range = >150k',
 'profession = engineer',
 'eye color = gray',
 'hobbies = reading',
 'nationality = Canadian']
# subset_indics = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]
#subset_indics = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39]
max_cardinal = 45
max_whitelist = 120
current_number = 100
number_of_tests = 100


def setup_module():
    print()
    print("__________Setup___Test PS DAC Scheme________")
    global pp_dac, dac_scheme, acc_scheme, pp_nizkp
    # create a signature object
    dac_scheme = DAC(max_cardinal= max_cardinal, max_whitelist = max_whitelist)
    # create public parameters with a trapdoor alpha
    (pp_dac,pp_nizkp) = dac_scheme.setup()
    acc_scheme = dac_scheme.acc_scheme

if __name__== "__main__" :
    setup_module()
    (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
    ## create issue key pair
    (isk, ipk) = dac_scheme.Issue_keygen(pp_dac, max_cardinal)
    ## create user key pair
    (usk, upk) = dac_scheme.user_keygen(pp_dac)
    ## create ra key pair
    (rpk, rsk) = dac_scheme.ra_keygen(pp_dac)
    ## create a proof for upk
    proof_usk = dac_scheme.EidApply(pp_nizkp, usk, upk)
    ## create a whitelist
    whitelist = []
    rndm_eid = order.random()
    whitelist.append(rndm_eid)
    total_time = 0
    for _ in range(number_of_tests):
        start_time = time.time()
        acc = (rndm_eid + rsk) * g_1
        end_time = time.time()    
        

        elapsed_time = (end_time - start_time) * 1000
        total_time += elapsed_time

    average_time = total_time / number_of_tests
    print(f"Average time for whitelist_add_time: {average_time} ms")
    
    for i in range(current_number):
        rndm_eid = order.random()
        whitelist.append(rndm_eid)

        acc = acc_scheme.AccAdd(acc, rndm_eid)

    F_x = poly_from_roots(whitelist, order)

    (whitelist, acc_prime, F_x_prime, eid, w_eid) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk)
    flag = dac_scheme.verify_EidRegister(pp_dac, rpk, acc_prime, eid, w_eid)

    

    # create an issue credc
    total_time = 0
    for _ in range(number_of_tests):
        start_time = time.time()
         # apply a eid
        #attrs = convert_mess_to_bn(message1_str)
        attrs = convert_mess_to_bn(SubList1_str)
        proof_usk = dac_scheme.CredObtain(pp_nizkp, upk, usk)
        (uk, cred) = dac_scheme.CredIssue(pp_dac, pp_nizkp, rpk, isk, upk, acc_prime, eid, w_eid, attrs, proof_usk)
        flag = dac_scheme.CredIssueCheck(pp_dac, ipk, usk, eid, attrs, uk, cred)
        end_time = time.time()    
        
        elapsed_time = (end_time - start_time) * 1000
        total_time += elapsed_time

    average_time = total_time / number_of_tests
    print(f"Average time for issue_time: {average_time} ms")

    # delegate
    # register a user
    (usk_prime, upk_prime) = dac_scheme.user_keygen(pp_dac)
    proof_usk_prime = dac_scheme.EidApply(pp_nizkp, usk_prime, upk_prime)
    (whitelist, acc_prime, F_x_prime, eid_prime, w_eid_prime) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc_prime, whitelist, F_x_prime, upk_prime, proof_usk_prime)

    # 
    proof_usk_prime = dac_scheme.CredDelegate_Receive_Pre(pp_nizkp, upk_prime, usk_prime)
    total_time = 0
    subset_indics = [0,1,2,3,4,5,6,7]
    for _ in range(number_of_tests):
        start_time = time.time()
        (uk_prime, k) = dac_scheme.CredDelegate_Pre(pp_dac, pp_nizkp, isk, cred, upk_prime, proof_usk_prime)
        (cm, pi_2) = dac_scheme.CredDelegate_Receive(pp_dac, usk_prime, eid_prime, acc_prime, rpk, w_eid_prime, uk_prime)
        cred_prime_I = dac_scheme.CredDelegate(pp_dac, pp_nizkp, ipk, usk, eid, uk_prime, cred, attrs, all_indics, subset_indics, acc_prime, rpk, upk_prime, proof_usk_prime, cm, k, isk, usk_prime, eid_prime, pi_2)
        flag = dac_scheme.CredDelegate_verify(pp_dac, ipk, usk_prime, eid_prime, uk_prime, cred_prime_I, subset_indics)
        end_time = time.time()    
        

        elapsed_time = (end_time - start_time) * 1000
        total_time += elapsed_time

    average_time = total_time / number_of_tests
    print(f"Average time for delegating a credential of user U to a user R: {average_time} ms")
    
    print ("Bool CredDelegate Verify", dac_scheme.CredDelegate_verify(pp_dac, ipk, usk_prime, eid_prime, uk_prime, cred_prime_I, subset_indics))

    CredDelegate_Pre_time = timeit.timeit('dac_scheme.CredDelegate_Pre(pp_dac, pp_nizkp, isk, cred, upk_prime, proof_usk_prime)', globals=globals(), number=number_of_tests)
    print(f"Average time for CredDelegate_Pre_time: {CredDelegate_Pre_time / number_of_tests:.6f} seconds")

    CredDelegate_Receive_time = timeit.timeit('dac_scheme.CredDelegate_Receive(pp_dac, usk_prime, eid_prime, acc_prime, rpk, w_eid_prime, uk_prime)', globals=globals(), number=number_of_tests)
    print(f"Average time for CredDelegate_Receive_time: {CredDelegate_Receive_time / number_of_tests:.6f} seconds")

    CredDelegate_time = timeit.timeit('dac_scheme.CredDelegate(pp_dac, pp_nizkp, ipk, usk, eid, uk_prime, cred, attrs, all_indics, subset_indics, acc_prime, rpk, upk_prime, proof_usk_prime, cm, k, isk, usk_prime, eid_prime, pi_2)', globals=globals(), number=number_of_tests)
    print(f"Average time for CredDelegate_time: {CredDelegate_time / number_of_tests:.6f} seconds")

    CredDelegate_verify_time = timeit.timeit('dac_scheme.CredDelegate_Receive(pp_dac, usk_prime, eid_prime, acc_prime, rpk, w_eid_prime, uk_prime)', globals=globals(), number=number_of_tests)
    print(f"Average time for CredDelegate_verify_time: {CredDelegate_verify_time / number_of_tests:.6f} seconds")

    print(f"Average time for delegator_time: {(CredDelegate_Pre_time + CredDelegate_time) / number_of_tests:.6f} seconds")

    print(f"Average time for delegatee_time: {(CredDelegate_Receive_time + CredDelegate_verify_time) / number_of_tests:.6f} seconds")



    S = [0,1,2,3,4,5]
    pi = dac_scheme.CredShow(pp_dac, ipk, rpk, usk, eid, w_eid, attrs, subset_indics, S, cred_prime_I)
    show_time = timeit.timeit('dac_scheme.CredShow(pp_dac, ipk, rpk, usk, eid, w_eid, attrs, subset_indics, S, cred_prime_I)', globals=globals(), number=number_of_tests)
    print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    CredVerify_time = timeit.timeit('dac_scheme.CredVerify(pp_dac, ipk, rpk, acc, pi, subset_indics, S, attrs)', globals=globals(), number=number_of_tests)
    print(f"Average time for verify_time: {CredVerify_time / number_of_tests:.6f} seconds")

    assert (dac_scheme.CredVerify(pp_dac, ipk, rpk, acc, pi, subset_indics, S, attrs)), ValueError("Credential is not correct")
    print()
    print("Checking if the credential is correct")

    # (acc_prime, whitelist) = dac_scheme.CredRevoke(pp_dac, rpk, rsk, eid_prime, acc_prime, whitelist)
    revoke_time = timeit.timeit('dac_scheme.CredRevoke(pp_dac, rpk, rsk, eid_prime, acc_prime, whitelist)', globals=globals(), number=number_of_tests)
    print(f"Average time for revoke_time: {revoke_time / number_of_tests:.6f} seconds")

