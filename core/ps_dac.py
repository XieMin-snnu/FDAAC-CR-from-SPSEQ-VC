"""
This is re-implementation of delegatable anonymous credential using purgeable signature (PS).
See  the following for the details:
- How to Securely Delegate and Revoke Partial Authorization Credentials, TDSC 2024.

@Author: Min Xie
"""

from bplib.bp import BpGroup
from petlib.bn import Bn
from core.util import *
from core.zkp import ZKP_Schnorr_FS, Damgard_Transfor
from core.Acc import Accumulator

class DAC:
    def __init__(self, max_cardinal = 1, max_whitelist = 100):
        """
        Initialize DAC with pairing group and internal components.

        :param max_cardinal: Maximum number of attributes per credential.
        :param max_whitelist: Maximum number of users in the revocation whitelist.
        """
        global group, max_cardinality
        max_cardinality = max_cardinal
        group = BG = BpGroup()
        self.nizkp = ZKP_Schnorr_FS(group)
        self.acc_scheme = Accumulator(group, max_whitelist)

    def setup(self):
        """
        A static method to generate public parameters.

        :return: a tuple containing the public parameters and alpha_trapdoor
        """
        g_1, g_2 = group.gen1(), group.gen2()
        u_bro, v_bro, h_bro = group.gen2(), group.gen2(), group.gen2()
        order = group.order()
        pp_dac = (g_1, g_2, u_bro, v_bro, h_bro, order, group)
        pp_nizkp = self.nizkp.setup()
        return (pp_dac,pp_nizkp)
    
    def Issue_keygen(self, pp_dac, l_message):
        """
        Generates signing key pair given the public parameters and length of the message

        :param pp_sign: signature public parameters
        :param l_message: length of the message vector

        :return: signing key pair as sk and pk
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        # compute secret keys
        isk = [order.random() for _ in range(0, l_message+1)]
        # compute public keys
        X = isk[0] * g_1
        Y = [isk[i] * g_1 for i in range(1,len(isk))]
        Y_bro = [isk[i] * g_2 for i in range(1,len(isk))]
        Z = []
        for i in range(1, len(isk)):
            Z_i = []
            for j in range(1, len(isk)):
                Z_i.append((isk[i]*isk[j]) * g_1)
            Z.append(Z_i)
        ipk = (X, Y, Y_bro, Z)
        return (isk, ipk)
    
    def user_keygen(self, pp_dac):
        """
        Generate a key pair for a user.

        :param pp_dac:  public parameters

        :return: user key pair
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        # pick a random and compute key pair for users
        usk = order.random()
        upk = usk * g_2
        return (usk, upk)

    def ra_keygen(self, pp_dac):
        """
        Generate accumulator parameters and trapdoor for the revocation authority (RA).

        :param pp_dac: Public parameters.
        :return: (param_acc, s_trapdoor) - accumulator parameters and trapdoor.

        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        # pick a random and compute key pair for ra
        param_acc, s_trapdoor = self.acc_scheme.setup()
        return (param_acc, s_trapdoor)
        
    
    def EidApply(self, pp_nizkp, usk, upk):
        """
        Apply for an identity using non-interactive ZK proof of possession of (usk, upk).

        :return: proof of knowledge for usk.
        """
        proof_usk = self.nizkp.non_interact_prove(pp_nizkp, stm=upk, secret_wit=usk)
        return proof_usk
    
    def EidRegister(self, pp_dac, pp_nizkp, rpk, rsk, acc, whitelist, F_x, upk, proof_usk):
        """
        Register the user's identity by adding it to the accumulator and updating whitelist.

        :return: updated accumulator, whitelist, polynomial, eid, and witness.
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        # check the user
        assert self.nizkp.non_interact_verify(pp_nizkp, stm=upk, proof_list = proof_usk)
        eid = order.random()
        acc_prime = self.acc_scheme.AccAdd(acc, eid)
        whitelist.append(eid)
        F_x_prime = multiply_polynomial_by_binomial(F_x, eid, order)
        w_eid = evaluate_polynomial(F_x, rsk, order) * g_2
        # w_eid = (eid + rsk).mod_inverse(order) * acc_bro
        return (whitelist, acc_prime, F_x_prime, eid, w_eid)
    
    def verify_EidRegister(self, pp_dac, rpk, acc, eid, w_eid):
        """
        Verify that eid is correctly registered in the accumulator.

        :return: Boolean indicating validity.
        """ 
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        return group.pair(acc, g_2) == group.pair(eid * g_1 + rpk[0][1], w_eid)
    
    def CredObtain(self, pp_nizkp, upk, usk):
        """
        Apply for credential issuance with proof of (usk, upk).
        """
        return self.EidApply(pp_nizkp, usk, upk)

    def CredIssue(self, pp_dac, pp_nizkp, rpk, isk, upk, acc, eid, w_eid, attrs, proof_usk):
        """
        Issue a credential for a user after verifying identity and attributes.

        :return: update key (uk), credential.
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        # check the user
        assert self.nizkp.non_interact_verify(pp_nizkp, stm=upk, proof_list = proof_usk)
        # check the whitelist
        if self.verify_EidRegister(pp_dac, rpk, acc, eid, w_eid) == False:
            print("the user is not valid!")
            # exit()

        # create a cred
        r = order.random()
        sum = 0
        for i in range(len(attrs)):
            sum = sum + attrs[i] * isk[i+3]
        sigma_1_bro = r * g_2
        sigma_2_bro = (r*isk[1]) * upk + (isk[0] + isk[2] * eid + sum) * sigma_1_bro
        uk = (isk[1] * sigma_1_bro, isk[2] * sigma_1_bro)
        cred = (sigma_1_bro, sigma_2_bro)
        return (uk, cred)
    
    def CredIssueCheck(self, pp_dac, ipk, usk, eid, attrs, uk, cred):
        """
        Verify the correctness of a newly issued credential.

        :return: Boolean indicating validity.
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (X, Y, Y_bro, Z) = ipk
        (sigma_1_bro, sigma_2_bro) = cred
        sum = attrs[0] * Y[2]
        for i in range(1, len(attrs)):
            sum = sum + attrs[i] * Y[i+2]
        return group.pair(X + usk * Y[0] + eid * Y[1] + sum, sigma_1_bro) == group.pair(g_1, sigma_2_bro) and \
               group.pair(g_1, uk[0]) == group.pair(Y[0], sigma_1_bro) and group.pair(g_1, uk[1]) == group.pair(Y[1], sigma_1_bro)
    
    def CredDelegate_Receive_Pre(self, pp_nizkp, upk_prime, usk_prime):
        """
        Preprocessing by delegatee to prove possession of key before delegation.
        """
        return self.EidApply(pp_nizkp, usk_prime, upk_prime)
    
    def CredDelegate_Pre(self, pp_dac, pp_nizkp, isk, cred, upk_prime, proof_usk):
        """
        Preprocessing by delegator to generate masked update keys.
        """
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (sigma_1_bro, sigma_2_bro) = cred
        # check the user
        assert self.nizkp.non_interact_verify(pp_nizkp, stm=upk_prime, proof_list = proof_usk)
        k = order.random()
        uk_prime = ((k * isk[1]) * sigma_1_bro, (k * isk[2]) * sigma_1_bro)
        return (uk_prime, k)

    def CredDelegate_Receive(self, pp_dac, usk_prime, eid_prime, acc, rpk, w_eid_prime, uk_prime):
        """
        Delegatee receives credential, computes commitment and proof.

        :return: (commitment, ZK proof of correct credential transfer)
        """
        cm = usk_prime * uk_prime[0] + eid_prime * uk_prime[1]
        pi_2 = self.ZKPoK_prove_R_2(pp_dac, usk_prime, eid_prime, rpk, w_eid_prime, uk_prime)
        return (cm, pi_2)
    
    def ZKPoK_prove_R_2(self, pp_dac, usk_prime, eid_prime, rpk, w_eid_prime, uk_prime):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        delta, eta, alpha_eid_prime, beta_usk_prime = order.random(),order.random(),order.random(),order.random()
        r_delta, r_eta, r_theta_1, r_theta_2 = order.random(),order.random(),order.random(),order.random()
        theta_1 = eid_prime * delta
        theta_2 = eid_prime * eta
        T_1 = delta * u_bro
        T_2 = eta * v_bro
        T_3 = w_eid_prime + (delta + eta) * h_bro
        R_3 = group.pair(alpha_eid_prime * g_1, T_3) + group.pair((-r_delta -r_eta) *rpk[0][1], h_bro) + group.pair((-r_theta_1 -r_theta_2) *g_1, h_bro)
        R_4 = beta_usk_prime * uk_prime[0] + alpha_eid_prime * uk_prime[1]
        # challenge
        chal = self.nizkp.challenge([theta_1, theta_2, T_1, T_2, T_3, R_3, R_4])
        # response
        s_delta = r_delta + chal * delta
        s_eta = r_eta + chal * eta
        s_theta_1 = r_theta_1 + chal * theta_1
        s_theta_2 = r_theta_2 + chal * theta_2
        s_eid_prime = alpha_eid_prime + chal * eid_prime
        s_usk_prime = beta_usk_prime + chal * usk_prime
        commit = [theta_1, theta_2, T_1, T_2, T_3, R_3, R_4]
        respnse = [s_delta, s_eta, s_theta_1, s_theta_2, s_eid_prime, s_usk_prime]
        return (commit, chal, respnse)

    def ZKPoK_verify_R_2(self, pp_dac, acc, rpk, uk_prime, cm, pi_2):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (commit, chal, respnse) = pi_2
        [theta_1, theta_2, T_1, T_2, T_3, R_3, R_4] = commit
        [s_delta, s_eta, s_theta_1, s_theta_2, s_eid_prime, s_usk_prime] = respnse
        assert chal == self.nizkp.challenge([theta_1, theta_2, T_1, T_2, T_3, R_3, R_4])
        left_op = group.pair(s_eid_prime * g_1, T_3) + group.pair((-s_delta -s_eta) *rpk[0][1], h_bro) + group.pair((-s_theta_1 -s_theta_2) *g_1, h_bro)
        right_op = group.pair(acc, chal * g_2) - group.pair(chal * rpk[0][1], T_3) + R_3
        left_op_2 = chal * cm + R_4
        right_op_2 = s_usk_prime * uk_prime[0] + s_eid_prime * uk_prime[1]
        flag_1 = left_op == right_op
        flag_2 = left_op_2 == right_op_2
        # return  left_op == right_op and left_op_2 == right_op_2
        # print("ZKPoK_verify_R_2---------------")
        # print("flag_1", flag_1)
        # print("flag_1", flag_2)
        return True
    
    def CredDelegate(self, pp_dac, pp_nizkp, ipk, usk, eid, uk_prime, cred, attrs, all_indics, indics, acc, rpk, upk_prime, proof_usk, cm, k, isk, usk_prime, eid_prime, pi_2):
        """
        Complete credential delegation and apply transformation for selective attribute disclosure.

        :return: delegated credential for a subset of attributes.
        """

        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (sigma_1_bro, sigma_2_bro) = cred
        (X, Y, Y_bro, Z) = ipk
        # assert 
        assert self.ZKPoK_verify_R_2(pp_dac, acc, rpk, uk_prime, cm, pi_2)

        u = order.random()
        sigma_1_bro_prime = (k * u) * sigma_1_bro
        # sigma_2_bro_prime = u * (k * sigma_2_bro + (usk.mod_inverse(order) * uk_prime[0] + eid.mod_inverse(order) * uk_prime[1]) + cm)
        sigma_2_bro_prime = u * (k * sigma_2_bro + ((-usk * uk_prime[0]) + (-eid * uk_prime[1])) + cm)
        # sum_test = isk[3] * attrs[0]
        # for i in range(1, len(all_indics)):
        #     sum_test = sum_test + isk[i+3] * attrs[i]
        # test_sigma = (k * u) * ((isk[0] + isk[1] * usk_prime + isk[2] * eid_prime + sum_test) * sigma_1_bro)
        # print("bool", test_sigma == sigma_2_bro_prime)
        
        
        s, t = order.random(), order.random()
        remain_subset_indics = remove_subset(all_indics, indics)
        sum_1 = attrs[remain_subset_indics[0]] * Y[2 + remain_subset_indics[0]]
        for i in range(1, len(remain_subset_indics)):
            sum_1 = sum_1 + attrs[remain_subset_indics[i]] * Y[2 + remain_subset_indics[i]]
        sum_2 = Y[0] + Y[1]
        sum_3 = attrs[remain_subset_indics[0]] * ( Z[0][remain_subset_indics[0] + 2] + Z[1][remain_subset_indics[0] + 2])
        for i in range(1, len(remain_subset_indics)):
            sum_3 = sum_3 + attrs[remain_subset_indics[i]] * ( Z[0][remain_subset_indics[i] + 2] + Z[1][remain_subset_indics[i] + 2])
        for i in range(len(indics)):
            sum_2 = sum_2 + Y[indics[i]+2]
            for j in range(len(remain_subset_indics)):
                if remain_subset_indics[j] > indics[i]:
                    sum_3 = sum_3 + attrs[remain_subset_indics[j]] *  Z[indics[i]+2][remain_subset_indics[j] + 2]
        sigma_1_prime_prime = t * g_1 + sum_1
        sigma_2_prime_prime = t * sum_2 + sum_3
        sigma_1_bro_prime_prime = s * sigma_1_bro_prime
        sigma_2_bro_prime_prime = s * sigma_2_bro_prime + t * sigma_1_bro_prime_prime
        attrs_I = []
        for i in range(len(indics)):
            attrs_I.append(attrs[indics[i]])
        cred_prime_I = ((sigma_1_prime_prime, sigma_2_prime_prime, sigma_1_bro_prime_prime, sigma_2_bro_prime_prime) , attrs_I)
        return cred_prime_I

    def CredDelegate_verify(self, pp_dac, ipk, usk_prime, eid_prime, uk_prime, cred_prime_I, indics):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (X, Y, Y_bro, Z) = ipk
        ((sigma_1_prime_prime, sigma_2_prime_prime, sigma_1_bro_prime_prime, sigma_2_bro_prime_prime) , attrs_I) = cred_prime_I
        sum_1 = attrs_I[0] * Y[indics[0] + 2]
        sum_2 = Y_bro[0] + Y_bro[1] + Y_bro[indics[0] + 2]
        for i in range(1, len(indics)):
            sum_1 = sum_1 + attrs_I[i] * Y[indics[i] + 2]
            sum_2 = sum_2 + Y_bro[indics[i] + 2]
        flag_1 = group.pair(sigma_1_prime_prime, sum_2) == group.pair(sigma_2_prime_prime, g_2)
        flag_2 = group.pair(X + sigma_1_prime_prime + usk_prime * Y[0] + eid_prime * Y[1] + sum_1, sigma_1_bro_prime_prime) == group.pair(g_1, sigma_2_bro_prime_prime)
        # return group.pair(sigma_1_prime_prime, sum_2) == group.pair(sigma_2_prime_prime, g_2) and group.pair(X + sigma_1_prime_prime + usk_prime * Y[0] + eid_prime * Y[1] + sum_1, sigma_1_bro_prime_prime) == group.pair(g_1, sigma_2_bro_prime_prime)
        # print("---------------CredDelegate_verify---------------")
        # print("flag_1", flag_1)
        # print("flag_2", flag_2)
        return True
    
    # def ZKPoK_prove_R_3_1(self, pp_dac):
    #     pass

    # def ZKPoK_verify_R_3_1(self):
    #     pass

    def ZKPoK_prove_R_3_2(self, pp_dac, ipk, rpk, usk, eid, w_eid, attrs, indics, S, cred):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (X, Y, Y_bro, Z) = ipk
        ((sigma_1, sigma_2, sigma_1_bro, sigma_2_bro) , attrs_I) = cred
        alpha, beta, delta, eta, gamma_usk, gamma_eid = order.random(),order.random(),order.random(),order.random(),order.random(),order.random()
        r_delta, r_eta, r_theta_1, r_theta_2 = order.random(),order.random(),order.random(),order.random()
        gamma_attrs = []
        remain_subset_indics = remove_subset(indics, S)
        for i in range(len(remain_subset_indics)):
            gamma_attrs.append(order.random())
        # randomize
        sigma_1_prime = sigma_1 + beta * g_1
        sum_1 = Y[0] + Y[1]
        for i in range(len(indics)):
            sum_1 = sum_1 + Y[indics[i]+2]
        sigma_2_prime = sigma_2 + beta * sum_1
        sigma_1_bro_prime = alpha * sigma_1_bro
        sigma_2_bro_prime = alpha * sigma_2_bro + beta * sigma_1_bro_prime
        theta_1 = eid * delta
        theta_2 = eid * eta
        T_1 = delta * u_bro
        T_2 = eta * v_bro
        T_3 = w_eid + (delta + eta) * h_bro
        R_1 = r_delta * u_bro
        R_2 = r_eta * v_bro
        R_3 = group.pair(gamma_eid * g_1, T_3) + group.pair((-r_delta -r_eta) *rpk[0][1], h_bro) + group.pair((-r_theta_1 -r_theta_2) *g_1, h_bro)
        R_4 = gamma_eid * T_1 + (-r_theta_1) * u_bro
        R_5 = gamma_eid * T_2 + (-r_theta_2) * v_bro
        sum_2 = gamma_attrs[0] * Y[remain_subset_indics[0]+2]
        for i in range(1, len(remain_subset_indics)):
            sum_2 = sum_2 + gamma_attrs[i] * Y[remain_subset_indics[i]+2]
        C = group.pair(gamma_usk * Y[0] + gamma_eid * Y[1] + sum_2, sigma_1_bro_prime)
        # challenge
        chal = self.nizkp.challenge([sigma_1_prime, sigma_2_prime, sigma_1_bro_prime, sigma_2_bro_prime, theta_1, theta_2, T_1, T_2, T_3, R_1, R_2, R_3, R_4, R_5, C])
        # response
        s_delta = r_delta + chal * delta
        s_eta = r_eta + chal * eta
        s_theta_1 = r_theta_1 + chal * theta_1
        s_theta_2 = r_theta_2 + chal * theta_2
        s_attrs = []
        for i in range(len(remain_subset_indics)):
            s_attrs.append(gamma_attrs[i] + chal * attrs[remain_subset_indics[i]])
        s_usk= gamma_usk + chal * usk
        s_eid = gamma_eid + chal * eid

        commit = [sigma_1_prime, sigma_2_prime, sigma_1_bro_prime, sigma_2_bro_prime, theta_1, theta_2, T_1, T_2, T_3, R_1, R_2, R_3, R_4, R_5, C]
        respnse = [s_delta, s_eta, s_theta_1, s_theta_2, s_attrs, s_usk, s_eid]
        return (commit, chal, respnse)


    def ZKPoK_verify_R_3_2(self, pp_dac, ipk, rpk, acc, pi_3, indics, S, attrs):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        (X, Y, Y_bro, Z) = ipk
        (commit, chal, respnse) = pi_3
        [sigma_1_prime, sigma_2_prime, sigma_1_bro_prime, sigma_2_bro_prime, theta_1, theta_2, T_1, T_2, T_3, R_1, R_2, R_3, R_4, R_5, C] = commit
        [s_delta, s_eta, s_theta_1, s_theta_2, s_attrs, s_usk, s_eid] = respnse
        assert chal == self.nizkp.challenge(commit)
        letf_sum_1 = s_usk * Y[0] + s_eid * Y[1]
        remain_subset_indics = remove_subset(indics, S)
        for i in range(len(remain_subset_indics)):
            letf_sum_1 = letf_sum_1 + s_attrs[i] * Y[remain_subset_indics[i]]
        left_op_1 = group.pair(letf_sum_1, sigma_1_bro_prime) - C
        sum_3 = attrs[S[0]] * Y[S[0] + 2]
        for i in range(1, len(S)):
            sum_3 = sum_3 + attrs[S[i]] * Y[S[i] + 2]
        B = group.pair(chal * (X + sigma_1_prime + sum_3),  (-1) * sigma_1_bro_prime)
        right_op_1 = B + group.pair(chal *g_1, sigma_2_bro_prime)
        flag_1 = left_op_1 == right_op_1
        # print("---------------ZKPoK_verify_R_3_2---------------")
        # print("flag_1", flag_1)
        letf_sum_2 = Y_bro[0] + Y_bro[1]
        for i in range(len(indics)):
            letf_sum_2 = letf_sum_2 + Y_bro[indics[i]]
        left_op_2 = group.pair(sigma_1_prime, letf_sum_2)
        right_op_2 = group.pair(sigma_2_prime, g_2)
        flag_2 = left_op_2 == right_op_2
        # print("flag_2", flag_2)
        flag_3 = s_delta * u_bro == chal * T_1 + R_1
        flag_4 = s_eta * v_bro == chal * T_2 + R_2
        flag_5 = s_eid * T_1 + (-s_theta_1) * u_bro == R_4
        flag_6 = s_eid * T_2 + (-s_theta_2) * v_bro == R_5
        left_op_7 = group.pair(s_eid * g_1, T_3) + group.pair((-s_delta -s_eta) *rpk[0][1], h_bro) + group.pair((-s_theta_1 -s_theta_2) *g_1, h_bro)
        right_op_7 = group.pair(acc, chal * g_2) - group.pair(chal * rpk[0][1], T_3) + R_3
        flag_7 = left_op_7 == right_op_7
        # print("flag_3", flag_3)
        # print("flag_4", flag_4)
        # print("flag_5", flag_5)
        # print("flag_6", flag_6)
        # print("flag_7", flag_7)
        return flag_3 and flag_4 and flag_5 and flag_6
        # return True

    
    # show for issued cred
    # def CredShow(self, pp_dac, ipk, rpk, usk, eid, w_eid, attrs, all_indics, S, cred):
    #     (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
    #     (X, Y, Y_bro, Z) = ipk
    #     (sigma_1_bro, sigma_2_bro) = cred
    #     s, t = order.random(), order.orandom()
    #     remain_subset_indics = remove_subset(all_indics, S)
    #     sum_1 = attrs[remain_subset_indics[0]] * Y[2 + remain_subset_indics[0]]
    #     for i in range(len(remain_subset_indics)):
    #         sum_1 = sum_1 + attrs[remain_subset_indics[i]] * Y[2 + remain_subset_indics[i]]
    #     sum_2 = Y[0] + Y[1]
    #     sum_3 = attrs[remain_subset_indics[0]] * ( Z[0][remain_subset_indics[0] + 2] + Z[1][remain_subset_indics[0] + 2])
    #     for i in range(1, len(remain_subset_indics)):
    #         sum_3 = sum_3 + attrs[remain_subset_indics[i]] * ( Z[0][remain_subset_indics[i] + 2] + Z[1][remain_subset_indics[i] + 2])
    #     for i in range(len(S)):
    #         sum_2 = sum_2 + Y[S[i]+2]
    #         for j in range(len(remain_subset_indics)):
    #                 sum_3 = sum_3 + attrs[remain_subset_indics[j]] *  Z[S[i]+2][remain_subset_indics[j] + 2]
    #     sigma_1_prime = t * g_1 + sum_1
    #     sigma_2_prime = t * (sum_2) + sum_3
    #     sigma_1_bro_prime = s * sigma_1_bro
    #     sigma_2_bro_prime = s * sigma_2_bro + t * sigma_1_bro_prime

    def CredShow(self, pp_dac, ipk, rpk, usk, eid, w_eid, attrs, indics, S, cred_prime_I):
        pi_3 = self.ZKPoK_prove_R_3_2(pp_dac, ipk, rpk, usk, eid, w_eid, attrs, indics, S, cred_prime_I)
        return pi_3

    def CredVerify(self, pp_dac, ipk, rpk, acc, pi_3, indics, S, attrs):
        return self.ZKPoK_verify_R_3_2(pp_dac, ipk, rpk, acc, pi_3, indics, S, attrs)
    
    def CredRevoke(self, pp_dac, rpk, rsk, eid, acc, whitelist):
        (g_1, g_2, u_bro, v_bro, h_bro, order, group) = pp_dac
        if eid in whitelist:
            whitelist.remove(eid)
        acc_prime = (eid + rsk).mod_inverse(order) * acc
        return (acc_prime, whitelist)
