"""
This is a Test (and example of how it works) of DAC protocol using purgeable signature (PS) in the TDSC 24 : ps_dac.py
This file contains unit tests for the functions in ps_da.py.
It tests the functions with different inputs and verifies that they produce the expected outputs.
"""

from bplib.bp import BpGroup
from core.ps_dac import DAC
from core.util import *


## messages sets as string type (attributes)
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

def setup_module(module):
    print()
    print("__________Setup___Test PS DAC Scheme________")
    global pp_dac, dac_scheme, acc_scheme, pp_nizkp
    # create a signature object
    dac_scheme = DAC(max_cardinal= max_cardinal, max_whitelist = max_whitelist)
    # create public parameters with a trapdoor alpha
    (pp_dac,pp_nizkp) = dac_scheme.setup()
    acc_scheme = dac_scheme.acc_scheme

def test_user_register() -> None:
    """Test the creation of a root credential."""
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
    acc = (rndm_eid + rsk) * g_1
    for i in range(current_number):
        rndm_eid = order.random()
        whitelist.append(rndm_eid)
        acc = acc_scheme.AccAdd(acc, rndm_eid)

    F_x = poly_from_roots(whitelist, order)

    # apply a eid
    (whitelist, acc_prime, F_x_prime, eid, w_eid) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk)

    # verify eid
    assert (dac_scheme.verify_EidRegister(pp_dac, rpk, acc_prime, eid, w_eid)), ValueError("Eid register is not correct")
    print()
    print("Registering a eid, and checking if the eid is correct")


def test_root_cred() -> None:
    """Test the creation of a root credential."""
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
    acc = (rndm_eid + rsk) * g_1
    for i in range(current_number):
        rndm_eid = order.random()
        whitelist.append(rndm_eid)
        acc = acc_scheme.AccAdd(acc, rndm_eid)

    F_x = poly_from_roots(whitelist, order)

    # apply a eid
    (whitelist, acc_prime, F_x_prime, eid, w_eid) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk)


    # create an issue cred
    attrs = convert_mess_to_bn(SubList1_str)
    proof_usk = dac_scheme.CredObtain(pp_nizkp, upk, usk)
    (uk, cred) = dac_scheme.CredIssue(pp_dac, pp_nizkp, rpk, isk, upk, acc_prime, eid, w_eid, attrs, proof_usk)
    # flag = dac_scheme.CredIssueCheck(pp_dac, ipk, usk, eid, attrs, uk, cred)

    # verify issue cred
    assert (dac_scheme.CredIssueCheck(pp_dac, ipk, usk, eid, attrs, uk, cred)), ValueError("Credential is not correct")
    print()
    print("Creating a root credential, and checking if the credential is correct")
    

def test_delegating() -> None:
    """Test the creation of a root credential."""
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
    
    acc = (rndm_eid + rsk) * g_1
    for i in range(current_number):
        rndm_eid = order.random()
        whitelist.append(rndm_eid)
        acc = acc_scheme.AccAdd(acc, rndm_eid)

    F_x = poly_from_roots(whitelist, order)

    # apply a eid
    (whitelist, acc_prime, F_x_prime, eid, w_eid) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk)


    # create an issue cred
    attrs = convert_mess_to_bn(SubList1_str)
    proof_usk = dac_scheme.CredObtain(pp_nizkp, upk, usk)
    (uk, cred) = dac_scheme.CredIssue(pp_dac, pp_nizkp, rpk, isk, upk, acc_prime, eid, w_eid, attrs, proof_usk)

    # delegate
    # register a user
    (usk_prime, upk_prime) = dac_scheme.user_keygen(pp_dac)
    proof_usk_prime = dac_scheme.EidApply(pp_nizkp, usk_prime, upk_prime)
    (whitelist, acc_prime, F_x_prime, eid_prime, w_eid_prime) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc_prime, whitelist, F_x_prime, upk_prime, proof_usk_prime)

    # 
    proof_usk_prime = dac_scheme.CredDelegate_Receive_Pre(pp_nizkp, upk_prime, usk_prime)
    subset_indics = [0,1,2,3,4,5,6,7]
    (uk_prime, k) = dac_scheme.CredDelegate_Pre(pp_dac, pp_nizkp, isk, cred, upk_prime, proof_usk_prime)
    (cm, pi_2) = dac_scheme.CredDelegate_Receive(pp_dac, usk_prime, eid_prime, acc_prime, rpk, w_eid_prime, uk_prime)
    cred_prime_I = dac_scheme.CredDelegate(pp_dac, pp_nizkp, ipk, usk, eid, uk_prime, cred, attrs, all_indics, subset_indics, acc_prime, rpk, upk_prime, proof_usk_prime, cm, k, isk, usk_prime, eid_prime, pi_2)
    
    ## check the correctness of credential
    assert (dac_scheme.CredDelegate_verify(pp_dac, ipk, usk_prime, eid_prime, uk_prime, cred_prime_I, subset_indics)), ValueError("Credential is not correct")
    print()
    print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")

def test_showing() -> None:
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
    
    acc = (rndm_eid + rsk) * g_1
    for i in range(current_number):
        rndm_eid = order.random()
        whitelist.append(rndm_eid)
        acc = acc_scheme.AccAdd(acc, rndm_eid)

    F_x = poly_from_roots(whitelist, order)

    # apply a eid
    (whitelist, acc_prime, F_x_prime, eid, w_eid) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk)


    # create an issue cred
    attrs = convert_mess_to_bn(SubList1_str)
    proof_usk = dac_scheme.CredObtain(pp_nizkp, upk, usk)
    (uk, cred) = dac_scheme.CredIssue(pp_dac, pp_nizkp, rpk, isk, upk, acc_prime, eid, w_eid, attrs, proof_usk)

    # delegate
    # register a user
    (usk_prime, upk_prime) = dac_scheme.user_keygen(pp_dac)
    proof_usk_prime = dac_scheme.EidApply(pp_nizkp, usk_prime, upk_prime)
    (whitelist, acc_prime, F_x_prime, eid_prime, w_eid_prime) = dac_scheme.EidRegister(pp_dac, pp_nizkp, rpk, rsk, acc_prime, whitelist, F_x_prime, upk_prime, proof_usk_prime)

    # 
    proof_usk_prime = dac_scheme.CredDelegate_Receive_Pre(pp_nizkp, upk_prime, usk_prime)
    subset_indics = [0,1,2,3,4,5,6,7]
    (uk_prime, k) = dac_scheme.CredDelegate_Pre(pp_dac, pp_nizkp, isk, cred, upk_prime, proof_usk_prime)
    (cm, pi_2) = dac_scheme.CredDelegate_Receive(pp_dac, usk_prime, eid_prime, acc_prime, rpk, w_eid_prime, uk_prime)
    cred_prime_I = dac_scheme.CredDelegate(pp_dac, pp_nizkp, ipk, usk, eid, uk_prime, cred, attrs, all_indics, subset_indics, acc_prime, rpk, upk_prime, proof_usk_prime, cm, k, isk, usk_prime, eid_prime, pi_2)
      
    ## check the correctness of credential
    assert (dac_scheme.CredDelegate_verify(pp_dac, ipk, usk_prime, eid_prime, uk_prime, cred_prime_I, subset_indics)), ValueError("Credential is not correct")
    print()
    print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")

    S = [0,1,2,3,4,5]
    pi = dac_scheme.CredShow(pp_dac, ipk, rpk, usk, eid, w_eid, attrs, subset_indics, S, cred_prime_I)
    assert (dac_scheme.CredVerify(pp_dac, ipk, rpk, acc, pi, subset_indics, S, attrs)), ValueError("Credential is not correct")
    print()
    print("Checking if the credential is correct")

