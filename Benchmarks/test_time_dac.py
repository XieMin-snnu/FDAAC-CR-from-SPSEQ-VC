import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bplib.bp import BpGroup
from core.dac import DAC
from core.spseq_uc import EQC_Sign
from core.zkp import ZKP_Schnorr_FS
import timeit
import random

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
 'nationality = Canadian']
subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18,19:19}
message2_str = ['gender = other',
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
 'eye color = green']
# message3_str = ["genther = male"]
# message1_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "componey = XX ", "driver license type = B"]
# subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18,19:19}
max_attr_number = 45
max_level_number = 15
# max_blacklist = 20
number_of_tests = 100

def setup_module():
    """Set up the DAC and return the necessary parameters and objects."""
    print("__________Setup___Test DAC ________")
    global EQ_Sign, dac, spseq_uc
    global pp, pp_dac, sk_ca, BG

    # create sign and nizk objest
    BG = BpGroup()
    nizkp = ZKP_Schnorr_FS(BG)
    spseq_uc = EQC_Sign(max_attr_number)

    # create dac obj, where t is max cardinality and l_message: the max number of the messagses
    dac = DAC(t = max_attr_number, l_message = max_level_number)

    # run setup to create public information of dac schemes
    (pp_dac, proof_vk, vk_stm, sk_ca, proof_alpha, alpha_stm) = dac.setup()
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac

if __name__== "__main__" :
    setup_module()
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
    ## create user key pair
    (usk, upk) = dac.user_keygen(pp_dac)
    ## create nym  and a proof for nym
    (nym_u, secret_nym_u, proof_nym_u) = dac.nym_gen(pp_dac, usk, upk)
    ## create a root credential
    Attr_vector = [message1_str, message2_str]

    issue_time = timeit.timeit('dac.issue_cred(pp_dac, attr_vector = Attr_vector, sk = sk_ca, nym_u = nym_u, k_prime = 11, proof_nym_u = proof_nym_u)', globals=globals(), number=number_of_tests)
    print(f"Average time for issue_time: {issue_time / number_of_tests:.6f} seconds")

    cred = dac.issue_cred(pp_dac, attr_vector = Attr_vector, sk = sk_ca, nym_u = nym_u, k_prime = 11, proof_nym_u = proof_nym_u)
    (sigma, update_key, commitment_vector, opening_vector) = cred
    ## check the correctness of root credential
    assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma)), ValueError("signature/credential is not correct")
    print()
    print("Creating a root credential, and checking if the credential is correct")

    ## prepare a proof
    # D = []
    # D.append(Attr_vector[0][:5])

    # #####################test show/verify ############################
    SubList1_str = ['living situation = with family', 'gender = male',]
    SubList2_str = ['height = 194', 'name = Diana', 'age = 35', 'salary range = 50k-100k']
    # SubList3_str = [,]
    D = [SubList1_str, SubList2_str]
    # D.append(Attr_vector[1][:5])
    # print("length",len(D))
    cred_show = (sigma, commitment_vector, opening_vector)
    proof = dac.proof_cred(pp_dac, nym_R = nym_u, aux_R = secret_nym_u, cred_R = cred_show, Attr=Attr_vector, D = D)

    show_time = timeit.timeit('dac.proof_cred(pp_dac, nym_R = nym_u, aux_R = secret_nym_u, cred_R = cred_show, Attr=Attr_vector, D = D)', globals=globals(), number=number_of_tests)
    print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    verify_time = timeit.timeit('dac.verify_proof(pp_dac, proof, D)', globals=globals(), number=number_of_tests)
    print(f"Average time for verify_time: {verify_time / number_of_tests:.6f} seconds")

    # ## check a proof
    # assert (dac.verify_proof(pp_dac, proof, D)) , ValueError("the credential is not valid")
    # print()
    # print("proving a credential to verifiers, and checking if the proof is correct")


    # issuing/delegating a credential of user U to a user R -------
    sub_mess_str = ["age = 30", "name = Alice ", "driver license type = B","genther = male", "componey = XX ", "driver license type = AB","genther = WWW", "componey = FF "]
    # Attr_vector.append(sub_mess_str)

    # ## generate key pair of user R
    (usk_R, upk_R) = dac.user_keygen(pp_dac)

    # ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)

    # ## create a credential for new nym_R: delegateor P -> delegatee R
    cred_R_U = dac.delegator(pp_dac, cred, sub_mess_str, l=3, sk_u=secret_nym_u, proof_nym=proof_nym_R)

    delegator_time = timeit.timeit('dac.delegator(pp_dac, cred, sub_mess_str, l=3, sk_u=secret_nym_u, proof_nym=proof_nym_R)', globals=globals(), number=number_of_tests)
    print(f"Average time for delegator_time: {delegator_time / number_of_tests:.6f} seconds")

    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = dac.delegatee(pp_dac, cred_R_U, sub_mess_str, secret_nym_R, nym_R)

    delegatee_time = timeit.timeit('dac.delegatee(pp_dac, cred_R_U, sub_mess_str, secret_nym_R, nym_R)', globals=globals(), number=number_of_tests)
    print(f"Average time for delegatee_time: {delegatee_time / number_of_tests:.6f} seconds")

    # print(f"Average time for delegating a credential of user U to a user R: {(delegatee_time + delegator_time)/ number_of_tests:.6f} seconds")

    # ## check the correctness of credential
    # assert (spseq_uc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, sigma_prime)), ValueError("signature/credential is not correct")
    # print()
    # print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")


    ##################test delegate_cred, show and verify cred######################
    # sub_mess_str = message1_str + message2_str
    #
    # test_index = 1
    # user_list = []
    # user_list.append([nym_u, secret_nym_u,proof_nym_u])
    # for i in range(test_index-1):
    #     (usk_R, upk_R) = dac.user_keygen(pp_dac)
    #     (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)
    #     user_list.append([nym_R, secret_nym_R, proof_nym_R])
    #
    # for i in range(test_index-1):
    #     # test_index
    #     Attr_vector.append(sub_mess_str)
    #     index_l = len(commitment_vector) + 1
    #     ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    #     cred_R_U = dac.delegator(pp_dac, cred, sub_mess_str, l=index_l, sk_u=user_list[i][1], proof_nym=user_list[i+1][2])
    #     (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = dac.delegatee(pp_dac, cred_R_U, sub_mess_str, user_list[i+1][1], user_list[i+1][0])
    #     print ("delegatee verify",spseq_uc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, sigma_prime))
    #     ## recreate a cred
    #     (sigma, update_key, commitment_vector, opening_vector)
    #     cred = (sigma_prime, update_key, rndmz_commitment_vector, rndmz_opening_vector)
    #
    #
    # SubList1_str = ['living situation = with family', 'gender = male','pet ownership = dog', 'favorite color = blue']
    # SubList2_str = ['gender = other', 'hair color = blonde']
    # # SubList3_str = []
    # D = [SubList1_str, SubList2_str]
    # # D.append(Attr_vector[1][:5])
    # # print("length",len(D))
    # cred_show = (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector)
    # proof = dac.proof_cred(pp_dac, nym_R = user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred_show, Attr=Attr_vector, D = D)
    #
    # show_time = timeit.timeit('dac.proof_cred(pp_dac, nym_R = user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred_show, Attr=Attr_vector, D = D)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")
    #
    # verify_time = timeit.timeit('dac.verify_proof(pp_dac, proof, D)', globals=globals(), number=number_of_tests)
    # print(f"Average time for verify_time: {verify_time / number_of_tests:.6f} seconds")

    # ## check a proof
    # # assert (dac.verify_proof(pp_dac, proof, D)) , ValueError("the credential is not valid")
    # print()
    # print("proving a credential to verifiers, and checking if the proof is correct")



    # # TEST delegate_cred, show and verify cred-------------
    # # delegate_cred
    # test_index = 10
    # user_list = []
    # # subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18}
    # user_list.append([nym_u, secret_nym_u,proof_nym_u])
    # for i in range(test_index-1):
    #     (usk_R, upk_R) = dac.user_keygen(pp_dac)
    #     (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)
    #     user_list.append([nym_R, secret_nym_R, proof_nym_R])

    # for i in range(test_index-1):
    #     # test_index
    #     index_l = len(commitment_vector) + 1
    #     ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    #     cred_R_U = dac.delegator(pp_dac, param_acc, vk_ca, cred, attr_str, index_l, sk_u=user_list[i][1], proof_nym=user_list[i+1][2], subset_indics_L = subset_indics)
    #     (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, delta) = dac.delegatee(pp_dac, vk_ca, cred_R_U, subset_indics, user_list[i+1][1], user_list[i+1][0])
    #     print ("delegatee verify",spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
    #     ## recreate a cred
    #     cred = (sigma_prime, update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime)
        
    # # show and verify cred 
    # len_non_list = 200
    # non_list_points = []
    # for i in range(len_non_list):
    #     non_list_points.append(Bn(random.randint(1,1000000)))
    # non_list = poly_from_roots(non_list_points,BG.order())
    # Acc_non = acc_scheme.AccCom(param_acc, non_list)
    # Acc_eva = evaluate_polynomial(non_list, s_trapdoor, order)

    # # open_subset
    # subset_indics_L = {0:0,1:1,2:2,3:3,4:4}
    # SubList1_str = attr_str[:5]
    # index_l = len(commitment_vector) 
    # ## prepare a proof
    # #  pp_dac, param_acc, vk_ca, nym_R, aux_R, cred_R, index_l, subset_indics, subset_str, non_list_coeffs
    # proof = dac.proof_cred(pp_dac, param_acc, vk_ca, user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)
    # # proof = dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R = secret_nym_u, cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)

    # # print(proof)
    # ## check a proof
    # print (dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)) 

    # show_time = timeit.timeit('dac.proof_cred(pp_dac, param_acc, vk_ca, user_list[test_index-1][0], aux_R = user_list[test_index-1][1], cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    # show_verify_time = timeit.timeit('dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_verify_time: {show_verify_time / number_of_tests:.6f} seconds")







    # ----------------------test opensubset-------------------------
    # # print("ID_list",ID_list)
    # len_non_list = 200
    # non_list_points = []
    # for i in range(len_non_list):
    #     non_list_points.append(Bn(random.randint(1,1000000)))
    # # print("non_list_points",non_list_points)
    # non_list = poly_from_roots(non_list_points,BG.order())
    # Acc_non = acc_scheme.AccCom(param_acc, non_list)
    # Acc_eva = evaluate_polynomial(non_list, s_trapdoor,order)

    # # open_subset
    # subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9}
    # # message1_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "componey = XX ", "driver license type = B"]
    # SubList1_str = attr_str[:3]
    # # print("length",len(SubList1_str))

    # ## prepare a proof
    # #  pp_dac, param_acc, vk_ca, nym_R, aux_R, cred_R, index_l, subset_indics, subset_str, non_list_coeffs
    # proof = dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R = secret_nym_u, cred_R = cred[:1]+cred[2:], index_l = index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs= non_list,Acc_eva = Acc_eva)

    # ## check a proof
    # print (dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)) 

    # show_time = timeit.timeit('dac.proof_cred(pp_dac, param_acc, vk_ca, nym_u, aux_R=secret_nym_u, cred_R=cred[:1]+cred[2:], index_l=index_l, subset_indics=subset_indics_L, subset_str=SubList1_str, non_list_coeffs=non_list,Acc_eva=Acc_eva)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_time: {show_time / number_of_tests:.6f} seconds")

    # show_verify_time = timeit.timeit('dac.verify_proof(pp_dac, param_acc, vk_ca, proof, SubList1_str, subset_indics_L, Acc_non)', globals=globals(), number=number_of_tests)
    # print(f"Average time for show_verify_time: {show_verify_time / number_of_tests:.6f} seconds")



    # print()
    # print("proving a credential to verifiers, and checking if the proof is correct")









    # # test -------------------U and R -------------------------

    # ## issuing/delegating a credential of user U to a user R -------
    # ## generate key pair of user R
    # (usk_R, upk_R) = dac.user_keygen(pp_dac)

    # ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    # (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)

    # index_l = len(commitment_vector)+1
    # subset_indics_L = {0:0,1:1}
    # SubList1_str = ["genther = male", "componey = XX "]
    # # subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17}
    # # SubList1_str = ["genther = male", "componey = XX ","driver license type = B","genther = male","componey = XX ", "driver license type = B",
    # #                 "genther = male", "componey = XX ","componey = XX ", "driver license type = B","genther = male", "componey = XX ","driver license type = B",
    # #                 "genther = male","componey = XX ", "driver license type = B","genther = male", "componey = XX "]

    # delegator_time = timeit.timeit('dac.delegator(pp_dac, param_acc, vk_ca, cred, SubList1_str, index_l, sk_u=secret_nym_u, proof_nym=proof_nym_R, subset_indics_L = subset_indics_L)', globals=globals(), number=number_of_tests)
    # print(f"Average time for delegator_time: {delegator_time / number_of_tests:.6f} seconds")

    # ## create a credential for new nym_R: delegateor P -> delegatee R
    # cred_R_U = dac.delegator(pp_dac, param_acc, vk_ca, cred, SubList1_str, index_l, sk_u=secret_nym_u, proof_nym=proof_nym_R, subset_indics_L = subset_indics_L)

    # delegatee_time = timeit.timeit('dac.delegatee(pp_dac, vk_ca, cred_R_U, SubList1_str, secret_nym_R, nym_R)', globals=globals(), number=number_of_tests)
    # print(f"Average time for delegatee_time: {delegatee_time / number_of_tests:.6f} seconds")
    
    # (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, delta) = dac.delegatee(pp_dac, vk_ca, cred_R_U, SubList1_str, secret_nym_R, nym_R)

    # print(f"Average time for Issuing/delegating a credential of user U to a user R: {(delegatee_time+delegator_time) / number_of_tests:.6f} seconds")
    # check the correctness of credential

    # print ("delegatee verify",spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
    # print()
    # print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")




    




    
