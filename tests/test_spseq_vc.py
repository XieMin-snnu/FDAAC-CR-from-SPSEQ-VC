"""
This is a Test (and example of how it works) of SPSEQ-UC signiture: spseq_vc.py
This file contains unit tests for the functions in spseq_vc.py.
It tests the functions with different inputs and verifies that they produce the expected outputs.
"""

from core.spseq_vc import EQC_Sign
from core.Acc import Accumulator

message1_str = ["genther = male", "componey = XX ", "driver license type = B"]
subset_indics = {0:0,1:1}
message2_str = ["genther = male", "componey = XX "]
message3_str = ["genther = male"]

def setup_module(module):
    print()
    print("__________Setup___Test SPEQ-VC Signature________")
    global pp, sign_scheme, param_acc
    # create a signature object
    sign_scheme =EQC_Sign(max_cardinal= 5)
    # create public parameters with a trapdoor alpha
    pp, alpha = sign_scheme.setup()
    param_acc, s_trapdoor = sign_scheme.acc_scheme.setup()

def test_sign():
    """Generate a signature and verify it"""

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    messages_vector = [message1_str]

    # create a signature sigma for user pk_u, without update_key
    (sigma, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics)

    # verify sigma
    assert(sign_scheme.verify(pp, vk, pk_u, commitment_vector, commit_2_vector, sigma)), ValueError("signiture is not correct")
    print()
    print("Generate a signature and verify it")

def test_changerep():
    """Generate a signature, run changrep function and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp

    # pick randomness mu and psi
    mu, upsilon = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

    # run changerep function (without randomizing update_key) to randomize the sign, pk_u and commitment vector
    (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta) = sign_scheme.Random_All(pp, vk, pk_u, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=False, update_key=None)

    # check the randomized signature is valid for the new values
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime)), ValueError("CahngeRep signiture is not correct")
    print()
    print("Generate a signature, run changrep function and verify if output of changrep (randomized sign) is correct")

def test_changerep_uk():
    """Generate a signature, run changrep function using update_key, randomize update_key (uk) and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp

    # pick randomness mu and psi
    mu, upsilon = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

   # run changerep function (without randomizing update_key) to randomize the sign, pk_u and commitment vector
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta) = sign_scheme.Random_All(pp, vk, pk_u, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=True, update_key=update_key)

    # check the randomized signature is valid for the new values
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime)), ValueError("CahngeRep signiture is not correct")
    print()
    print("Generate a signature, run changrep function using update_key, randomize signature and update_key (uk) and verify all")

def test_changerel_from_sign():
    """Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it"""
    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a user key pair
    (sk_l, pk_l) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

    # run changerel function (with update_key) to add commitment C3 (for message3_str) to the sign where index L = 3
    index_l = 2
    subset_indics_L = {0:0}

    (sigma_tilde, commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime) =sign_scheme.Delegate(pp, param_acc, message3_str, index_l, pk_l, 
                                                                                                            sigma, commitment_vector, monypol_vector, commit_2_vector, F_ID, ID_list, update_key, subset_indics_L)

    # check if the new signature is valid for C1, C2, C3 where C3 is the new commitment
    assert (sign_scheme.verify(pp, vk, pk_u, commitment_vector_new, commit_2_vector_new, sigma_tilde)), ValueError("CahngeRel Signiture from Sign is not correct")
    print()
    print("Generate a signature, run changrel function, which adds one additional commitment using update_key (uk), and verify the new signature with the extended commitment")


def test_changerel_from_rep():
    """run changrel on the signature that is coming from cgangrep (that is already randomized) and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp

    # pick randomness mu and psi
    mu, upsilon = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a user key pair for delegate
    (sk_l, pk_l) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

     # run changerep function (without randomizing update_key) to randomize the sign, pk_u and commitment vector
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta) = sign_scheme.Random_All(pp, vk, pk_u, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=True, update_key=update_key)

    # run changerel function (with update_key) to add commitment C3 (for message3_str) to the sign where index L = 3
    index_l = 2
    subset_indics_L = {0:0}

    (sigma_tilde, commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime) =sign_scheme.Delegate(pp, param_acc, message3_str, index_l, pk_l, 
                                                                                                            sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID, ID_list, rndmz_update_key, subset_indics_L, mu)

    # check if the new signature is valid for C1, C2, C3 where C3 is the new commitment
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, commitment_vector_new, commit_2_vector_new, sigma_tilde)), ValueError("CahngeRel on signature from Rep is not correct")
    print()
    print("Run changrel on the signature that is coming from cgangrep (that is already randomized) and verify it")

def test_convert():
    """run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify it"""
    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a user key pair
    (sk_l, pk_l) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

    # run convert protocol between sender and receiver to create signature for new pk
    sigma_orpha = sign_scheme.send_convert_sig(vk, sk_u, sigma)
    sigma_new = sign_scheme.receive_convert_sig(vk, sk_l, sigma_orpha)

    # check if the new signature is valid for pk_new
    assert(sign_scheme.verify(pp, vk, pk_l, commitment_vector, commit_2_vector, sigma_new))
    print()
    print("run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify the new signature for new pk_u it")


def test_ukverify():
    """verify the completeness of usign_key"""
    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    messages_vector=[message1_str]

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = sign_scheme.sign(pp, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime=4)

    # check if the new signature is valid for pk_new
    assert(sign_scheme.uk_verify(pp, param_acc, vk, update_key, sigma))
    print()
    print("run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify the new signature for new pk_u it")
