"""
This implementation of Accumulator.
See  the following for the details:
@Author: Min Xie
"""
from bplib.bp import BpGroup
from binascii import hexlify
from hashlib import sha256
from numpy.polynomial.polynomial import polyfromroots,polysub,polydiv
from petlib.bn import Bn
from core.util import *


class Accumulator:
    def __init__(self, group, max_cardinal = 10):
        """
        Initializes a SetCommitment object.

        :param BG: bilinear pairing groups
        :param max_cardinal: the maximum cardinality t (default value is 1)
        """
        self.max_cardinality = max_cardinal
        self.G = group

    def setup(self):
        """
        A method to generate public parameters.

        :return: a tuple containing the public parameters and alpha_trapdoor
        """
        self.g_1, self.g_2 = self.G.gen1(), self.G.gen2()
        self.order = self.G.order()
        self.s_trapdoor = self.order.random()
        pp_acc_G1 = [self.g_1.mul(self.s_trapdoor.pow(i)) for i in range(self.max_cardinality)]
        pp_acc_G2 = [self.g_2.mul(self.s_trapdoor.pow(i)) for i in range(self.max_cardinality)]
        param_acc = (pp_acc_G1, pp_acc_G2)
        return param_acc, self.s_trapdoor
    
    def BlindCom(self, param_acc, com_usign):
        (pp_acc_G1, pp_acc_G2) = param_acc
        E_1 = pp_acc_G1[1]
        E_2 = {}
        for key,value in com_usign.items():
                E_2[key] = self.s_trapdoor * value
        return E_1,E_2
    
    def AccCom(self,param_acc,F_x,G2_Element=False):
        (pp_acc_G1, pp_acc_G2) = param_acc
        if G2_Element:
            coeffs_points = [(pp_acc_G2.__getitem__(i)).mul(F_x[i])for i in range(len(F_x))]
        else:
            coeffs_points = [(pp_acc_G1.__getitem__(i)).mul(F_x[i])for i in range(len(F_x))]
        Acc = ec_sum(coeffs_points)
        return Acc
    
    def AccAdd(self, acc_com, point):
        acc_com_prime = ((point + self.s_trapdoor)%self.order) * acc_com
        return acc_com_prime
    
    def MemberProve(self, param_acc, F_x, y, G2_Element=False):
        (pp_acc_G1, pp_acc_G2) = param_acc
        # quotient_points = [element for element in points if element != y]
        # quotient_coeffs = polynomial_with_roots_in_add(quotient_points,self.order)
        coeff_subset = poly_from_roots([y],self.order)
        quotient_coeffs,remainder_coeffs = poly_div_mod(F_x,coeff_subset,self.order)
        if G2_Element:
            coeffs_points = [(pp_acc_G2.__getitem__(i)).mul(quotient_coeffs[i])for i in range(len(quotient_coeffs))]
        else:
            coeffs_points = [(pp_acc_G1.__getitem__(i)).mul(quotient_coeffs[i])for i in range(len(quotient_coeffs))]
        pi_member = ec_sum(coeffs_points)
        return pi_member
    
    def NonMemberProve(self, F_non_coeffs, F_x_coeffs, F_non_eva = None):
        if F_non_eva is None:
            F_non = evaluate_polynomial(F_non_coeffs,self.s_trapdoor,self.order)
        else:
            F_non = F_non_eva
        F_x = evaluate_polynomial(F_x_coeffs,self.s_trapdoor,self.order)
        if F_x == 0 or F_non == 0:
            raise Exception("Invalid trapdoor: polynomial evaluates to 0, retrying...")
        # print("F_non_coeffs",F_non_coeffs)
        # print("F_x_coeffs",F_x_coeffs)
        gcd, alpha, beta = extended_gcd(F_non, F_x)
        # print("gcd",gcd)
        if gcd == 1: 
            pi_non_member = (Bn.from_num(alpha) * self.g_2, Bn.from_num(beta) * self.g_1)
            return pi_non_member
        elif gcd != Bn(1):
            # raise Exception("F_non(s), F_x(s) not coprime, retrying...")
            return False
    
    def MemberVerify(self, Acc, pi_member, c_y, G2_Element=False):
        if G2_Element:
            return (self.G.pair(self.g_1, Acc) == self.G.pair(c_y, pi_member))
        else:
            return (self.G.pair(Acc, self.g_2) == self.G.pair(pi_member, c_y))
    
    def NonMemberVerify(self, Acc, pi_non_member, Acc_com, aux = False):
        (alpha_G, beta_G) = pi_non_member
        gt_sum = product_GT([self.G.pair(Acc, alpha_G), self.G.pair(beta_G, Acc_com)])
        if aux:
            return  gt_sum == self.G.pair(self.g_1, aux)
        else:
            return  gt_sum == self.G.pair(self.g_1, self.g_2)