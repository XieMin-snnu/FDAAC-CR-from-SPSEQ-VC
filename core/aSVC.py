"""
This implementation of Vector commitments with Re-Random properties .
These commitments can be used to build SPSQE-VC signatures and their application delegatable anonymous credential.
See the following for the details
 -FDAAC-CR: Practical Delegatable Attribute-Based Anonymous Credentials with Fine-grained Delegation Management and Chainable Revocation.

@Author: Min Xie
"""
from bplib.bp import BpGroup
from binascii import hexlify
from hashlib import sha256
from numpy.polynomial.polynomial import polyfromroots,polysub,polydiv
from petlib.bn import Bn
from core.util import *
from core.zkp import ZKP_Schnorr_FS


class VectorCommitment:
    def __init__(self, max_cardinal = 1):
        """
        Initializes a SetCommitment object.

        :param BG: bilinear pairing groups
        :param max_cardinal: the maximum cardinality t (default value is 1)
        """
        global group, max_cardinality, Schnorr_FS
        max_cardinality = max_cardinal
        group = BG = BpGroup()
        Schnorr_FS = ZKP_Schnorr_FS(BG)

    @staticmethod
    def setup():
        """
        A static method to generate public parameters.

        :return: a tuple containing the public parameters and alpha_trapdoor
        """
        g_1, g_2 = group.gen1(), group.gen2()
        order = group.order()
        alpha_trapdoor = order.random()
        pp_commit_G1 = [g_1.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        pp_commit_G2 = [g_2.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        roots_of_unity = generate_integer_roots_of_unity(order,max_cardinality)
        # print("roots_of_unity:",roots_of_unity)
        basic_coeffs = lagrange_basic_interpolation(roots_of_unity,order)
        # print("Interpolated polynomial coefficients (Bn objects):", monypol_coeff)
        # basic_coeffs = lagrange_interpolation(points,order)
        lagrange_basic_G_list = []
        # create group elements using the coefficent and public info
        for j, coeffs in enumerate(basic_coeffs):
            lagrange_basic_G_points = [(pp_commit_G1.__getitem__(i)).mul(basic_coeffs[j][i])for i in range(len(basic_coeffs[j]))]
            lagrange_basic_G = ec_sum(lagrange_basic_G_points)
            lagrange_basic_G_list.append(lagrange_basic_G)
        param_sc = (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list)
        return param_sc, alpha_trapdoor

    def commit_set(self, param_sc,  mess_set_str, indics = False):
        """
          Commits to a set.

        :param param_sc: public parameters as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
        :param mess_set_str: a message set as a string

        :return: a set commitment and related opening information
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc

        mess_set = convert_mess_to_bn(mess_set_str)
        basic_coeffs_mess = []
        if indics:
            for k,v in indics.items():
                basic_coeffs_mess.append(basic_coeffs[v])
        else:
            basic_coeffs_mess = basic_coeffs

        # convert string to Zp and compute \FI

        # test sig
        monypol_coeff = lagrange_interpolation(basic_coeffs_mess,mess_set,order)
        # monypol_coeff = []

        # convert string to Zp
        # mess_set = convert_mess_to_bn(mess_set_str)
        
        # generate len(set) root of unity
        
            # print(f"Basis polynomial {i} coefficients (Bn objects):", coeffs)
        # rho = group.order().random()

        # create group elements using the coefficent and public info
        # coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]

        # create a vector commitment
        commitment = ec_sum_with_coeffs(lagrange_basic_G_list[:len(mess_set)],mess_set)
        return (commitment,monypol_coeff)


    def open_set(self, param_sc, commitment, mess_set_str):
        """
        Verifies the opening information of a set.

        :param param_sc: public parameters
        :param commitment: the set commitment
        :param open_info: the opening info of commitment
        :param mess_set_str: the message set
        :return: true if evolution is correct, false otherwise
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc

        mess_set = convert_mess_to_bn(mess_set_str)

        monypol_coeff = lagrange_interpolation(basic_coeffs,mess_set,order)

        #pre compitation to recompute the commitment
        coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]
        re_commit = ec_sum(coef_points)

        #check if the regenerated commitment is match with the orginal commitment
        return re_commit == commitment

    def open_subset(self, param_sc, monypol_coeff, subset_indics, subset_str):
        """
        Generates a witness for the subset

        :param param_sc: public parameters
        :param mess_set_str: the messagfe set
        :param open_info: opening information
        :param subset_str: a subset of the message set

        :return: a witness for the subset
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc

        # convert the string to BN elements
        mess_subset_t = convert_mess_to_bn(subset_str)
        roots_subset = []
        basic_coeffs_subset = []
        for i in range(len(subset_indics)):
            roots_subset.append(roots_of_unity[subset_indics[i]])
            basic_coeffs_subset.append(basic_coeffs[subset_indics[i]])
        # A_I(X) Polynomial
        coeff_subset_indics = polynomial_with_roots(roots_subset,order)
        # R_I(X) Polynomial
        monypol_subset_coeffs = lagrange_interpolation(basic_coeffs_subset,mess_subset_t,order)

        # \FI(X)-R_I(X)
        temp_coeffs = poly_sub(monypol_coeff,monypol_subset_coeffs,order)
        # Quotient Polynomial Q(X),R_I(X) = \FI(X)/A_I(X)
        # quotient_coeffs,remainder_coeffs = poly_div_mod(monypol_coeff,coeff_subset_indics,order)
        quotient_coeffs,remainder_coeffs = poly_div_mod(temp_coeffs,coeff_subset_indics,order)
        # print("monypol_coeff",monypol_coeff)
        # print("coeff_subset_indics",coeff_subset_indics)
        # print("quotient_coeffs",quotient_coeffs)
        # print("remainder_coeffs",remainder_coeffs)
        # print("monypol_subset_coeffs",monypol_subset_coeffs)

        # compute a witness for subset mess_subset_t
        witn_groups = [(pp_commit_G1.__getitem__(i)).mul(quotient_coeffs[i])for i in range(len(quotient_coeffs))]
        witness = ec_sum(witn_groups)
        return witness

    def verify_subset(self, param_sc, commitment, subset_indics, subset_str, witness, R=None):
        """
        Verifies if witness proves that subset_str is a subset of the original message set.


        :param param_sc: set commitment public parameters
        :param commitment: commitment
        :param subset_str: subset message
        :param witness: witness to prove subset message in message set
        :return: 0 or 1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc
        # convert messagse to BN type
        mess_subset_t = convert_mess_to_bn(subset_str)
        # obtain specified subset for indics
        roots_subset,basic_coeffs_subset = [],[]

        for i in range(len(subset_indics)):
            roots_subset.append(roots_of_unity[subset_indics[i]])
            basic_coeffs_subset.append(basic_coeffs[subset_indics[i]])

        # A_I(X) Polynomial
        coeff_subset_indics = polynomial_with_roots(roots_subset,order)
        # R_I(X) Polynomial
        monypol_subset_coeffs = lagrange_interpolation(basic_coeffs_subset,mess_subset_t,order)

        subset_indics_group_elements =[(pp_commit_G2.__getitem__(i)).mul(coeff_subset_indics[i])for i in range(len(coeff_subset_indics))]
        subset_indics_group = ec_sum(subset_indics_group_elements)

        monypol_subset_group_elements =[(pp_commit_G1.__getitem__(i)).mul(monypol_subset_coeffs[i])for i in range(len(monypol_subset_coeffs))]
        monypol_subset_group = ec_sum(monypol_subset_group_elements)

        if R is None:
            return group.pair(commitment, g_2) ==  group.pair(witness, subset_indics_group) * group.pair(monypol_subset_group, g_2)
        else:
            state = [R,(mess_subset_t,subset_indics)]
            s = Schnorr_FS.challenge(state)
            S = g_2.mul(s)
            U = S + R
            return group.pair(commitment, g_2) ==  group.pair(witness, subset_indics_group) * group.pair(monypol_subset_group, U)

    def Random_OpenSubset(self, param_sc, commitment, subset_indics, subset_str, witness):
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc
        # convert messagse to BN type
        mess_subset_t = convert_mess_to_bn(subset_str)
        # pick a randomness r and commit it
        (u,R) = self.Random_Gen(param_sc,(mess_subset_t,subset_indics))
        commitment_Ran = commitment.mul(u)
        witness_Ran = witness.mul(u)
        return (commitment_Ran,witness_Ran,R)

    def Random_Gen(self, param_sc,aux=None):
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = param_sc
        # pick a randomness r and commit it
        r = order.random()
        R = g_2.mul(r)
        # computes a randomness s
        state = [R,aux]
        s = Schnorr_FS.challenge(state)
        # compute the final randomness u
        u = (r + s) % order
        return (u,R)