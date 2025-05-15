
from core.dac_cr import DAC
from bplib.bp import BpGroup
from core.util import *
import timeit
import random

message1_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "componey = XX ", "driver license type = B"]
#subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18,19:19}
#subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11}
subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9}
#subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18,19:19,20:20,21:21,22:22,23:23,24:24,25:25,26:26,27:27,28:28,29:29,30:30,31:31,32:32,33:33,34:34,35:35,36:36,37:37,38:38,39:39}
# message2_str = ["genther = male", "componey = XX "]
# message3_str = ["genther = male"]
max_attr_number = 45
max_level_number = 15
max_blacklist = 30
number_of_tests = 100

def setup_module():
    """Set up the DAC and return the necessary parameters and objects."""
    print("__________Setup___Test DAC ________")
    global dac, spseq_vc,acc_scheme
    global pp_dac, vk_ca, sk_ca, param_acc, s_trapdoor, BG, g_1, g_2, order, group

    # create sign and nizk objest
    BG = BpGroup()
    # create dac obj, where t is max cardinality and l_message: the max number of the messagses
    dac = DAC(t = max_attr_number, l_message = max_level_number, max_blacklist = max_blacklist)
    spseq_vc = dac.spseq_vc
    nizkp = dac.nizkp
    acc_scheme = dac.acc_scheme
    # run setup to create public information of dac schemes
    pp_dac = dac.setup()
    (pp_sign, pp_zkp, pp_nizkp) = pp_dac
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
    (sk_ca, vk_ca) = dac.ca_keygen(pp_dac)
    (param_acc, s_trapdoor) = dac.ra_keygen()

if __name__== "__main__" :
    setup_module()
    (pp_sign, pp_zkp, pp_nizkp) = pp_dac
    ## create user key pair
    (usk, upk) = dac.user_keygen(pp_dac)
    ## create nym  and a proof for nym
    (nym_u, secret_nym_u, proof_nym_u) = dac.nym_gen(pp_dac, usk, upk)
    ## create a root credential
    attr_str = message1_str+message1_str#+message1_str+message1_str

    cred = dac.issue_cred(pp_dac, param_acc, vk_ca, attr_vector=[attr_str], subset_indics = subset_indics, sk = sk_ca, nym_u = nym_u, k_prime = 10, proof_nym_u = proof_nym_u)
    issue_time = timeit.timeit('dac.issue_cred(pp_dac, param_acc, vk_ca, attr_vector=[attr_str], subset_indics = subset_indics, sk = sk_ca, nym_u = nym_u, k_prime = 10, proof_nym_u = proof_nym_u)', globals=globals(), number=number_of_tests)
    print(f"Average time for issue_time: {issue_time / number_of_tests:.6f} seconds")

    (sigma, update_key, commitment_vector, monypol_vector, commit_2_vector,F_ID,ID_list) = cred




    # # TEST delegate_cred, show and verify cred-------------
    # # delegate_cred
    test_index = 3
    user_list = []
    # subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18}
    user_list.append([nym_u, secret_nym_u,proof_nym_u])
    for i in range(test_index-1):
        (usk_R, upk_R) = dac.user_keygen(pp_dac)
        (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)
        user_list.append([nym_R, secret_nym_R, proof_nym_R])
    subset_indics_L = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7}
    SubList1_str = attr_str[:8]
    for i in range(test_index-1):
        # test_index
        index_l = len(commitment_vector) + 1
        ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
        cred_R_U = dac.delegator(pp_dac, param_acc, vk_ca, cred, SubList1_str, index_l, sk_u=user_list[i][1], proof_nym=user_list[i+1][2], subset_indics_L = subset_indics_L)
        (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, delta) = dac.delegatee(pp_dac, vk_ca, cred_R_U, subset_indics, user_list[i+1][1], user_list[i+1][0])
        #print ("delegatee verify",spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
        ## recreate a cred
        #print(rndmz_monypol_vector)
        cred = (sigma_prime, update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime)
        
    # # # show and verify cred 
    len_non_list = 20
    non_list_points = []
    for i in range(len_non_list):
        non_list_points.append(Bn(random.randint(1,1000000)))
    non_list = poly_from_roots(non_list_points,BG.order())
    Acc_non = acc_scheme.AccCom(param_acc, non_list)
    Acc_eva = evaluate_polynomial(non_list, s_trapdoor, order)

    # open_subset
    subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5}
    SubList1_str = attr_str[:6]
    index_l = len(commitment_vector)
    # # ## prepare a proof
    # # #  pp_dac, param_acc, vk_ca, nym_R, aux_R, cred_R, index_l, subset_indics, subset_str, non_list_coeffs
    proof = dac.proof_cred(pp_dac, param_acc, vk_ca, user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)
    # # proof = dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R = secret_nym_u, cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)

    # # print(proof)
    # ## check a proof
    # print (dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)) 

    show_time = timeit.timeit('dac.proof_cred(pp_dac, param_acc, vk_ca, user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)', globals=globals(), number=number_of_tests)
    print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    show_verify_time = timeit.timeit('dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)', globals=globals(), number=number_of_tests)
    print(f"Average time for show_verify_time: {show_verify_time / number_of_tests:.6f} seconds")







    # ----------------------test opensubset for level 1-------------------------
    # # print("ID_list",ID_list)
    # len_non_list = 20
    # non_list_points = []
    # for i in range(len_non_list):
    #     non_list_points.append(Bn(random.randint(1,1000000)))
    # # print("non_list_points",non_list_points)
    # non_list = poly_from_roots(non_list_points,BG.order())
    # Acc_non = acc_scheme.AccCom(param_acc, non_list)
    # Acc_eva = evaluate_polynomial(non_list, s_trapdoor,order)

    # # open_subset
    # # subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17}
    # subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5}
    # # message1_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "componey = XX ", "driver license type = B"]
    # SubList1_str = attr_str[:6]
    # print("length",len(SubList1_str))

    # ## prepare a proof
    # #  pp_dac, param_acc, vk_ca, nym_R, aux_R, cred_R, index_l, subset_indics, subset_str, non_list_coeffs
    # proof = dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R = secret_nym_u, cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)

    # ## check a proof
    # # print (dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)) 

    # show_time = timeit.timeit('dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R=secret_nym_u, cred_R=cred[:1]+cred[2:], index_l=index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs=non_list,Acc_eva=Acc_eva)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    # show_verify_time = timeit.timeit('dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_verify_time: {show_verify_time / number_of_tests:.6f} seconds")



    # print()
    # print("proving a credential to verifiers, and checking if the proof is correct")









    # test -------------------U and R -------------------------

    # issuing/delegating a credential of user U to a user R -------
    # generate key pair of user R
    (usk_R, upk_R) = dac.user_keygen(pp_dac)

    # ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)

    index_l = len(commitment_vector)+1
    subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7}
    SubList1_str = attr_str[:8]
    # subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17}
    # SubList1_str = ["genther = male", "componey = XX ","driver license type = B","genther = male","componey = XX ", "driver license type = B",
    #                 "genther = male", "componey = XX ","componey = XX ", "driver license type = B","genther = male", "componey = XX ","driver license type = B",
    #                 "genther = male","componey = XX ", "driver license type = B","genther = male", "componey = XX "]

    delegator_time = timeit.timeit('dac.delegator(pp_dac, param_acc, vk_ca, cred, SubList1_str, index_l, sk_u=secret_nym_u, proof_nym=proof_nym_R, subset_indics_L = subset_indics_L)', globals=globals(), number=number_of_tests)
    print(f"Average time for delegator_time: {delegator_time / number_of_tests:.6f} seconds")

    ## create a credential for new nym_R: delegateor P -> delegatee R
    cred_R_U = dac.delegator(pp_dac, param_acc, vk_ca, cred, SubList1_str, index_l, sk_u=secret_nym_u, proof_nym=proof_nym_R, subset_indics_L = subset_indics_L)

    delegatee_time = timeit.timeit('dac.delegatee(pp_dac, vk_ca, cred_R_U, SubList1_str, secret_nym_R, nym_R)', globals=globals(), number=number_of_tests)
    print(f"Average time for delegatee_time: {delegatee_time / number_of_tests:.6f} seconds")
    
    (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, delta) = dac.delegatee(pp_dac, vk_ca, cred_R_U, SubList1_str, secret_nym_R, nym_R)

    #print(f"Average time for Issuing/delegating a credential of user U to a user R: {(delegatee_time+delegator_time) / number_of_tests:.6f} seconds")
    # check the correctness of credential

    # print ("delegatee verify",spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
    # print()
    # print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")




    




    
