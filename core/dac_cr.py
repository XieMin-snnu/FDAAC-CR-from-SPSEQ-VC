"""
This implementation of FDAAC-CR using SPSQE-VC signatures and Accumulator.

@Author: Min Xie
"""
from bplib.bp import BpGroup
from core.spseq_vc import EQC_Sign
from core.zkp import ZKP_Schnorr_FS, Damgard_Transfor
from core.util import *
import time

class DAC:
    def __init__(self, t, l_message, max_blacklist):
        """
        Initialize the DAC (Delegatable Anonymous Credential) scheme.

        :param t: Maximum number of attributes/messages per credential.
        :param l_message: Maximum length of attribute vectors.
        :param max_blacklist: Maximum number of blacklisted identities.

        Initializes underlying primitives including:
        - SPSEQ-VC signature and vector commitment schemes
        - Set accumulator
        - Zero-knowledge proof (ZKP) systems for both interactive and non-interactive scenarios
        """
        global group, order
        group = BpGroup()
        order = BpGroup().order()
        self.t = t
        self.l_message = l_message
        # create objects of underlines schemes
        self.spseq_vc = EQC_Sign(t,max_blacklist)
        self.vc_scheme = self.spseq_vc.vc_scheme
        self.acc_scheme = self.spseq_vc.acc_scheme
        self.nizkp = ZKP_Schnorr_FS(group)
        self.zkp = Damgard_Transfor(group)

    def setup(self):
        """
         the DAC scheme public parameters
        """
        # create public parameters and signing pair keys
        pp_sign, alpha = self.spseq_vc.setup()
        
        pp_zkp = self.zkp.setup(group)
        pp_nizkp = self.nizkp.setup()
        # (G, g, o) = pp_nizkp

        # "create proof of vk and alpha trpdoor -> vk_stm and alpha_stm are the statements need to be proved "
        # X_0 = vk_ca.pop(0)
        # vk_stm = vk_ca.copy()
        # proof_vk = self.nizkp.non_interact_prove(pp_nizkp, stm=vk_stm, secret_wit=sk_ca)
        # alpha_stm = alpha * g
        # proof_alpha = self.nizkp.non_interact_prove(pp_nizkp, stm=alpha_stm, secret_wit=alpha)
        # vk_ca.insert(0, X_0)
        pp_dac = (pp_sign,pp_zkp,pp_nizkp)
        return pp_dac
    
    def ca_keygen(self, pp_dac):
        """
        Generate a key pair for a ca.

        :param pp_dac:  public parameters

        :return: user key pair
        """
        (pp_sign,pp_zkp,pp_nizkp) = pp_dac
        (sk_ca, vk_ca) = self.spseq_vc.sign_keygen(pp_sign, l_message=self.l_message)
        return (sk_ca, vk_ca)
    
    def ra_keygen(self):
        """
        Generate a key pair for a ra.

        :param pp_dac:  public parameters

        :return: user key pair
        """
        param_acc, s_trapdoor = self.acc_scheme.setup()
        return (param_acc, s_trapdoor)

    def user_keygen(self, pp_dac):
        """
        Generate a key pair for a user.

        :param pp_dac:  public parameters

        :return: user key pair
        """
        (pp_sign,pp_zkp,pp_nizkp) = pp_dac
        (usk, upk) = self.spseq_vc.user_keygen(pp_sign)
        return (usk, upk)

    def nym_gen(self, pp_dac, usk, upk):
        """
        Generate a pseudonym (nym) and related zero-knowledge proof for a user.

        :param pp_dac: DAC public parameters.
        :param usk: User secret key.
        :param upk: User public key.

        :return: (nym, secret_witness, proof_nym_u) - The pseudonym, its secret witness, and proof of correctness.
        """
        (pp_sign,pp_zkp,pp_nizkp) = pp_dac
        (G, g, o, h) = pp_zkp
        # pick randomness
        psi, chi = order.random(), order.random()

        # create a nym and aux for it
        nym = self.spseq_vc.rndmz_pk(pp_sign, upk, psi, chi)
        secret_wit = psi * (usk + chi)

        # create a proof for nym
        (pedersen_commit, pedersen_open) = self.zkp.announce()
        (open_randomness, announce_randomnes, announce_element) = pedersen_open
        state = ['schnorr', g, h, pedersen_commit.__hash__()]
        challenge = self.zkp.challenge(state)
        response = self.zkp.response(challenge, announce_randomnes, stm=nym, secret_wit=secret_wit)
        proof_nym_u = (challenge, pedersen_open, pedersen_commit, nym, response)

        return (nym, secret_wit, proof_nym_u)

    def issue_cred(self, pp_dac, param_acc, vk_ca, attr_vector, subset_indics, sk, nym_u, k_prime, proof_nym_u):
        """
        Issue a root credential to a user after verifying their pseudonym proof.

        :param pp_dac: DAC public parameters.
        :param param_acc: Accumulator parameters.
        :param vk_ca: Verification key of the CA.
        :param attr_vector: Attribute vector to be signed.
        :param subset_indics: Indices of attributes that are delegatable.
        :param sk: CA secret key.
        :param nym_u: User pseudonym.
        :param k_prime: (Optional) Index for update key generation.
        :param proof_nym_u: ZKP proof for pseudonym correctness.

        :return: Credential (with or without update key depending on delegation support).
        """
        (pp_sign, pp_zkp, pp_nizkp) = pp_dac
        challenge, pedersen_open, pedersen_commit, stm, response = proof_nym_u

        # check if proof of nym is correct
        if self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response) == True:
            # check if delegate keys is provided
            if k_prime != None:
                (sigma, update_key, commitment_vector, monypol_vector,commit_2_vector, F_ID, ID_list) = self.spseq_vc.sign(pp_sign, param_acc, nym_u, sk, attr_vector, subset_indics, k_prime=k_prime)
                cred = (sigma, update_key, commitment_vector, monypol_vector, commit_2_vector,F_ID, ID_list)
                # assert(self.spseq_vc.verify(pp_sign, vk_ca, nym_u, commitment_vector, commit_2_vector, sigma)), ValueError("signature/credential is not correct")
                return cred
            else:
                (sigma, commitment_vector, monypol_vector,commit_2_vector,F_ID, ID_list) = self.spseq_vc.sign(pp_sign, param_acc, nym_u, sk, attr_vector, subset_indics)
                cred = (sigma, commitment_vector, monypol_vector,commit_2_vector,F_ID, ID_list)
                # assert (self.spseq_vc.verify(pp_sign, vk_ca, nym_u, commitment_vector, commit_2_vector, sigma)), ValueError(
                    # "signature/credential is not correct")
                return cred
        else:
            raise ValueError("proof of nym is not valid ")

    def proof_cred(self, pp_dac, param_acc, vk_ca, nym_R, aux_R, cred_R, index_l, subset_indics, subset_str, non_list_coeffs, Acc_eva = None):
        """
        Generate a zero-knowledge proof of credential possession with selective attribute disclosure.

        :param pp_dac: DAC public parameters.
        :param param_acc: Accumulator parameters.
        :param vk_ca: Verification key of the CA.
        :param nym_R: Prover's pseudonym.
        :param aux_R: Auxiliary information related to nym_R.
        :param cred_R: Credential associated with nym_R.
        :param index_l: Level of users.
        :param subset_indics: Indices of disclosed attributes.
        :param subset_str: Disclosed attribute values.
        :param non_list_coeffs: Non-membership witness coefficients.
        :param Acc_eva: Accumulator evaluation (optional).

        :return: A proof demonstrating correct possession and disclosure of selected attributes.
        """

        (pp_sign, pp_zkp, pp_nizkp) = pp_dac
        (G, g, o, h) = pp_zkp
        (sigma, commitment_vector, monypol_vector,commit_2_vector,F_ID,ID_list) = cred_R
        # pick randomness
        mess_subset_t = convert_mess_to_bn(subset_str)
        (mu,R) = self.vc_scheme.Random_Gen(pp_sign,(mess_subset_t,subset_indics))
        upsilon,rio = order.random(),order.random()
        # run change rep to randomize credential and user pk (i.e., create a new nym)
        (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, nym_P, delta) = self.spseq_vc.Random_All \
            (pp_sign, vk_ca, nym_R, commitment_vector, monypol_vector,commit_2_vector, sigma, mu, upsilon, B=False, update_key=None)
        
        # ID_coeffs = poly_from_roots(ID_list,order)
        # print("ID_list",ID_list)
        non_member_proof = self.acc_scheme.NonMemberProve(non_list_coeffs, F_ID, Acc_eva)
        # print(non_member_proof)
        if non_member_proof == False:
            # raise Exception("Witness generation failed, Please check input disjointness, retrying...")
            return False
        (alpha_G, beta_G)= non_member_proof
        rndmz_non_member_proof = (mu * alpha_G, rio.mod_inverse(order) * beta_G)
        

        # create an announcement
        (pedersen_commit, pedersen_open) = self.zkp.announce()
        (open_randomness, announce_randomnes, announce_element) = pedersen_open

        # get a challenge
        state = ['schnorr', g, h, pedersen_commit.__hash__()]
        challenge = self.zkp.challenge(state)

        # prover creates a respoonse (or proof)
        response = self.zkp.response(challenge, announce_randomnes, stm=nym_P, secret_wit= (aux_R + delta) * upsilon )
        proof_nym_p = (challenge, pedersen_open, pedersen_commit, nym_P, response)
        # create a witness for the attributes set that needed to be disclosed
        Witness = self.vc_scheme.open_subset(pp_sign, monypol_vector[index_l-1], subset_indics, subset_str)
        rndmz_witness = Witness.mul(mu)

        
        # Acc membership relation
        acc_ID = self.acc_scheme.AccCom(param_acc,F_ID,True)
        rndmz_acc_ID = ((mu*rio) % order) * acc_ID
        rndmz_member_proof_list = []
        # print("len(ID_list)", len(ID_list))
        for i in range(len(ID_list)):
            rndmz_member_proof_list.append(rio * self.acc_scheme.MemberProve(param_acc,F_ID,ID_list[i],True))

        # rndmz_acc_ID = G
        # rndmz_member_proof_list = []
        
        
        # output the whole proof
        proof = (sigma_prime, rndmz_commitment_vector, rndmz_commit_2_vector, nym_P, rndmz_witness, proof_nym_p, rndmz_acc_ID, R, rndmz_member_proof_list, rndmz_non_member_proof)
        return proof

    def verify_proof(self, pp_dac, param_acc, vk_ca, proof, subset_str, subset_indics, acc_non):
        """
        Verify a credential proof including:
        - Signature validity
        - ZKP of pseudonym
        - Attribute opening correctness
        - Membership and non-membership in the accumulator

        :param pp_dac: DAC public parameters.
        :param param_acc: Accumulator parameters.
        :param vk_ca: Verification key of the CA.
        :param proof: Proof to verify.
        :param subset_str: Disclosed attribute values.
        :param subset_indics: Indices of disclosed attributes.
        :param acc_non: Non-membership accumulator.

        :return: Boolean indicating whether the proof is valid.
        """
        (pp_sign, pp_zkp, pp_nizkp) = pp_dac
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (sigma_prime, rndmz_commitment_vector, rndmz_commit_2_vector, nym_P, rndmz_witness, proof_nym_p, rndmz_acc_ID, R, rndmz_member_proof_list, rndmz_non_member_proof) = proof
        (challenge, pedersen_open, pedersen_commit, nym_P, response) = proof_nym_p
        mess_subset_t = convert_mess_to_bn(subset_str)
        state = [R,(mess_subset_t,subset_indics)]
        s = self.nizkp.challenge(state)
        S = g_2.mul(s)
        U = S + R

        Flag_member = True
        for i in range(len(rndmz_commit_2_vector)):
            Flag_member = Flag_member and self.acc_scheme.MemberVerify(rndmz_acc_ID, rndmz_member_proof_list[i], rndmz_commit_2_vector[i], True)
        
        # open = self.vc_scheme.verify_subset(pp_sign,  rndmz_commitment_vector[len(rndmz_commitment_vector)-1], subset_indics, subset_str, rndmz_witness, R)
        # sigma = self.spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime)
        # zkp = self.spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime)
        # nonmember = self.acc_scheme.NonMemberVerify(acc_non, rndmz_non_member_proof, rndmz_acc_ID, U)
        # print("membership",Flag_member)
        # print("open",self.vc_scheme.verify_subset(pp_sign,  rndmz_commitment_vector[len(rndmz_commitment_vector)-1], subset_indics, subset_str, rndmz_witness, R))
        # print("sigma",self.spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
        # print("zkp",self.zkp.verify(challenge, pedersen_open, pedersen_commit, nym_P, response))
        # print("non-member",self.acc_scheme.NonMemberVerify(acc_non, rndmz_non_member_proof, rndmz_acc_ID, U))
        # check the proof is valid for D
        return self.vc_scheme.verify_subset(pp_sign,  rndmz_commitment_vector[len(rndmz_commitment_vector)-1], subset_indics, subset_str, rndmz_witness, R) and \
                self.zkp.verify(challenge, pedersen_open, pedersen_commit, nym_P, response) and self.spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime) and \
                Flag_member and self.acc_scheme.NonMemberVerify(acc_non, rndmz_non_member_proof, rndmz_acc_ID, U) == True
    
        return True
    

    def revoke_cred(self, param_acc, s_trapdoor, acc_non, ID_l):
        """
        Revoke a credential by adding an identity to the non-membership accumulator.

        :param param_acc: Accumulator parameters.
        :param s_trapdoor: Trapdoor for accumulator.
        :param acc_non: Current accumulator state.
        :param ID_l: Identity to revoke.

        :return: Updated accumulator.
        """
        return self.acc_scheme.AccAdd(param_acc,acc_non, ID_l)

    """
    This is the delegation phase or the issuing credential protocol in the paper between the delegator and delegatee. 
    """

    def delegator(self, pp_dac, param_acc, vk_ca, cred_u, A_l, index_l, sk_u, proof_nym, subset_indics_L,k_prime=None):
        """
        Generate a delegatable credential for another user (delegatee) based on an existing credential.

        :param pp_dac: DAC public parameters.
        :param param_acc: Accumulator parameters.
        :param vk_ca: Verification key of CA.
        :param cred_u: Original credential from delegator.
        :param A_l: Attributes to add to the credential.
        :param index_l: Index for the new user.
        :param sk_u: Delegator's secret key.
        :param proof_nym: Delegatee's pseudonym proof.
        :param subset_indics_L: Delegatable subset of attributes.
        :param k_prime: Optional index for update key.

        :return: Credential ready for delegatee to bind with their own secret key.
        """
        (pp_sign, pp_zkp, pp_nizkp) = pp_dac
        challenge, pedersen_open, pedersen_commit, stm, response = proof_nym
        nym_R = stm

        # check the proof
        assert self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response)

        (sigma, update_key, commitment_vector, monypol_vector, commit_2_vector,F_ID, ID_list) = cred_u
        # run change rep to add an attributes set l into the credential
        (Sigma_tilde, Commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime) = self.spseq_vc.Delegate(pp_sign, param_acc, 
                                                                 A_l, index_l, nym_R, sigma, commitment_vector, monypol_vector, commit_2_vector, F_ID, ID_list, update_key, subset_indics_L)

        # print("----------or-----------",self.spseq_vc.verify(pp_sign, vk_ca, nym_R, commitment_vector_new, commit_2_vector_new, Sigma_tilde))
        
        # run convert signature for sender to remove secret key for the credential
        sigma_orpha = self.spseq_vc.send_convert_sig(vk_ca, sk_u, Sigma_tilde)
        # output a new credential for the additional attribute set and  ready to be added a new user secret key
        cred_R = (sigma_orpha, Commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime)
        return cred_R

    def delegatee(self, pp_dac, vk_ca, cred, A_l, sk_R, nym_R, sk_P_Return=False):
        """
        Finalize credential delegation by binding the credential to the delegatee's secret key.

        :param pp_dac: DAC public parameters.
        :param vk_ca: Verification key of CA.
        :param cred: Credential obtained from delegator.
        :param A_l: Additional attribute set.
        :param sk_R: Delegatee's secret key.
        :param nym_R: Delegatee's pseudonym.
        :param sk_P_Return: Whether to return the derived secret key (for testing or verification).

        :return: Final credential tuple for the delegatee, with randomized commitment and pseudonym.
        """
        (pp_sign, pp_zkp, pp_nizkp) = pp_dac
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (sigma_orpha, Commitment_L, monypol_L, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime) = cred
        # convert signature receiver part to add the new user secret key into the credential
        sigma_change = self.spseq_vc.receive_convert_sig(vk_ca, sk_R, sigma_orpha)
        # pick randomness
        mu, upsilon = order.random(), order.random()
        # run changrep to randomize and hide the whole credential
        (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, nym_P, delta) = self.spseq_vc.Random_All \
            (pp_sign, vk_ca, nym_R, commitment_vector_new, monypol_vector_new, commit_2_vector_new, sigma_change, mu, upsilon, B=False,
             update_key=None)
        # print("---------ee------------",self.spseq_vc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, rndmz_commit_2_vector, sigma_prime))
        # output a new credential for the additional attribute set as well as the new user
        if sk_P_Return:
            sk_P = ((sk_R + delta) * upsilon)% order
            print(nym_R == sk_P*g_1)
            cred_R = (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, sk_P, delta)
        else:
            cred_R = (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, F_ID_prime, ID_list_prime, nym_P, delta)
        return cred_R

        # test --dele and show
        # delta = order.random()
        # cred_R = (sigma_change, commitment_vector_new, monypol_vector_new, commit_2_vector_new, F_ID_prime, ID_list_prime, nym_R, delta)
        # return cred_R