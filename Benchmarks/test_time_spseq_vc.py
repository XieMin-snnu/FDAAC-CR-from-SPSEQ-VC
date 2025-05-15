import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.spseq_vc_pure import EQC_Sign # type: ignore
import timeit

message1_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "componey = XX ", "driver license type = B",]
message2_str = ['living situation = with family',
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
 'eye color = green']
subset_indics_1 = {0:0,1:1,2:2,3:3,4:4,5:5,6:6}
subset_indics_2 = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12}
subset_indics_3 = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9}
subset_indics = {0:0,1:1,2:2,3:3,4:4,5:5,6:6,7:7,8:8,9:9,10:10,11:11,12:12,13:13,14:14,15:15,16:16,17:17,18:18,19:19}
# message2_str = ["genther = male", "componey = XX "]
# message3_str = ["genther = male"]


def setup_module():
    print()
    print("__________Setup___Test SPEQ-VC Signature________")
    global pp, sign_scheme, param_acc
    # create a signature object
    sign_scheme =EQC_Sign(max_cardinal= 55)
    # create public parameters with a trapdoor alpha
    pp, alpha = sign_scheme.setup()
    param_acc, s_trapdoor = sign_scheme.acc_scheme.setup()

if __name__== "__main__" :
    setup_module()
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp

    # pick randomness mu and psi
    mu, upsilon = group.order().random(), group.order().random()

    number_of_tests = 100

    # sign_keygen_time = timeit.timeit('sign_scheme.sign_keygen(pp_sign=pp, l_message=3)', globals=globals(), number=number_of_tests)
    # print(f"Average time for sign_keygen: {sign_keygen_time / number_of_tests:.6f} seconds")

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=15)

    # user_keygen_time = timeit.timeit('sign_scheme.user_keygen(pp)', globals=globals(), number=number_of_tests)
    # print(f"Average time for user_keygen: {user_keygen_time / number_of_tests:.6f} seconds")

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a user key pair for delegate
    (sk_l, pk_l) = sign_scheme.user_keygen(pp)

    message1_str_40 =message1_str+message1_str+message1_str#+message1_str+message1_str

    messages_vector=[message1_str_40]

    sign_time = timeit.timeit('sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics_3, k_prime=11)', globals=globals(), number=number_of_tests)
    print(f"Average time for sign_time: {sign_time / number_of_tests:.6f} seconds")



    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics_1, k_prime=11)

    # print(f"+++++++++++++++++: {len(update_key['usign_1']):.6f} seconds")

    Random_All_time = timeit.timeit(
        'sign_scheme.Random_All(pp, vk, pk_u, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=True, update_key=update_key)',
        globals=globals(), number=number_of_tests)
    print(f"Average time for Random_All_time: {Random_All_time / number_of_tests:.6f} seconds")

    # send_convert_sig_time = timeit.timeit('sign_scheme.send_convert_sig(vk, sk_u, sigma)', globals=globals(), number=number_of_tests)
    # print(f"Average time for send_convert_sig_time: {send_convert_sig_time / number_of_tests:.6f} seconds")

    sigma_orpha = sign_scheme.send_convert_sig(vk, sk_u, sigma)

    # receive_convert_sig_time = timeit.timeit('sign_scheme.receive_convert_sig(vk, sk_l, sigma_orpha)', globals=globals(), number=number_of_tests)
    # print(f"Average time for receive_convert_sig_time: {receive_convert_sig_time / number_of_tests:.6f} seconds")

    sigma_new = sign_scheme.receive_convert_sig(vk, sk_l, sigma_orpha)

    # uk_verify_time = timeit.timeit('sign_scheme.uk_verify(pp, param_acc, vk, update_key, sigma)', globals=globals(), number=number_of_tests)
    # print(f"Average time for uk_verify_time: {uk_verify_time / number_of_tests:.6f} seconds")

    # print("uk_verify:",sign_scheme.uk_verify(pp, param_acc, vk, update_key, sigma))



    # run changerep function (without randomizing update_key) to randomize the sign, pk_u and commitment vector
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta) = sign_scheme.Random_All(pp, vk, pk_u, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=True, update_key=update_key)

    sign_verify_time = timeit.timeit('sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime)', globals=globals(), number=number_of_tests)
    print(f"Average time for sign_verify_time: {sign_verify_time / number_of_tests:.6f} seconds")
    # check the randomized signature is valid for the new values
    # print("Randomed sign verify:",sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))

    index_l = len(messages_vector)+1
    subset_indics_L = {0:0,1:1,2:2,3:3,4:4,5:5}
    message3_str = ["genther = male", "componey = XX ", "driver license type = B","genther = male", "componey = XX ", "driver license type = B"]

    Delegate_time = timeit.timeit('sign_scheme.Delegate(pp, param_acc, message3_str, index_l, pk_l, sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_update_key, subset_indics_L, mu)', globals=globals(), number=number_of_tests)
    print(f"Average time for Delegate_time: {Delegate_time / number_of_tests:.6f} seconds")



    # (sigma_tilde, commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new) =sign_scheme.Delegate(pp, param_acc, message3_str, index_l, pk_l, 
    #                                                                                                         sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_update_key, subset_indics_L, mu)
    
    # print("Delegated sign verify",sign_scheme.verify(pp, vk, rndmz_pk_u, commitment_vector_new, commit_2_vector_new, sigma_tilde))

    




    
