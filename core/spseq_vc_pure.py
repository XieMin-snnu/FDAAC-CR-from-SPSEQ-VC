"""
This implementation of SPSQE-VC signature (pure version without considering FDAAC-CR). It uses proposed Vector commitments with Re-Random properties as an ingredient
See the following for the details
 -FDAAC-CR: Practical Delegatable Attribute-Based Anonymous Credentials with Fine-grained Delegation Management and Chainable Revocation.
   
@Author: Min Xie
"""

from core.aSVC import VectorCommitment
from core.zkp import ZKP_Schnorr_FS
from core.Acc import Accumulator
from core.util import *

class EQC_Sign:
    def __init__(self, max_cardinal = 1, max_blacklist =10):
        """ Initializes the EQC_Sign class """
        global max_cardinality, group,Schnorr_FS
        group = BpGroup()
        max_cardinality = max_cardinal
        self.vc_scheme = VectorCommitment(max_cardinal)
        Schnorr_FS = ZKP_Schnorr_FS(group)
        self.acc_scheme = Accumulator(group, max_blacklist)

    def setup(self):
        """
        Sets up the signature scheme by creating public parameters and a secret key
        :return: public parameters and secret key
        """
        pp_sign, alpha = self.vc_scheme.setup()
        return pp_sign, alpha

    def sign_keygen(self, pp_sign, l_message):
        """
        Generates signing key pair given the public parameters and length of the message

        :param pp_sign: signature public parameters
        :param l_message: length of the message vector

        :return: signing key pair as sk and pk
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        # compute secret keys
        x = order.random()
        x_i = [order.random() for _ in range(0, l_message+1)]
        x_i_prime = [order.random() for _ in range(0, l_message+1)]
        sk = {
            "x":x,
            "x_i":x_i,
            "x_i_prime":x_i_prime
        }
        # compute public keys
        vk_x = [sk["x"]* g_1, sk["x"]* g_2]
        vk_x_i = [sk["x_i"][i] * g_2 for i in range(len(sk["x_i"]))]
        vk_x_i_prime = [sk["x_i_prime"][i] * g_2 for i in range(len(sk["x_i_prime"]))]
        # compute X_0 keys that is used for delegation
        vk = {
            "x":vk_x,
            "x_i":vk_x_i,
            "x_i_prime":vk_x_i_prime
        }
        return (sk, vk)

    def user_keygen(self, pp_sign):
        """
        Generates a user key pair given the public parameters

        :param pp_sign: signature public parameters
        :return: a user key pair
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        # pick a random and compute key pair for users
        sk_u = order.random()
        pk_u = sk_u * g_1
        return (sk_u, pk_u)

    def encode(self, pp_sign, mess_set,subset_indics_L=False):
        """
        Encodes a message set into a set commitment with opening information

        :param pp_sign: signature public parameters
        :param mess_set: a message set

        :return: a commitment and opening information
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        # commit to set using vc scheme 
        commitment, monypol_coeff =  self.vc_scheme.commit_set(pp_sign, mess_set,subset_indics_L)
        return (commitment, monypol_coeff)

    def rndmz_commit(self, commitment_vector, monypol_vector, mu):
        """
        Randomizes a commitment and opening vectors with a given randomness mu.

        :param commitment_vector:
        :param opening_vector:
        :param mu: a randomness
        :return: a randomized commitment and opening information
        """
        rndmz_commit_vector = [mu * item for item in commitment_vector]
        rndmz_monypol_vector = []
        return (rndmz_commit_vector, rndmz_monypol_vector)
    
    def rndmz_commit_2(self, commit_2_vector, mu):
        """
        Randomizes a commitment and opening vectors with a given randomness mu.

        :param commitment_vector:
        :param opening_vector:
        :param mu: a randomness
        :return: a randomized commitment and opening information
        """
        rndmz_commit_2_vector = [mu * item for item in commit_2_vector]
        return (rndmz_commit_2_vector)

    def rndmz_pk(self,pp_sign, pk_u, psi, chi):
        """
        Randomizes a public key with two given randomness psi and chi.

        :param pp_sign: signature public parameters
        :param pk_u: user public key
        :param psi: randomness uses to randomize public key
        :param chi: randomness uses to randomize public key

        :return: randomized public key
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        # randomize pk as described in the paper
        rndmz_pk_u= psi * (pk_u + chi * g_1)
        return rndmz_pk_u

    def sign(self, pp_sign, param_acc, pk_u, sk, messages_vector, subset_indics, k_prime = None):
        """
        Generates a signature for the commitment and related opening information along with update key.

        :param pp_sign:signature public parameters
        :param pk_u: user public key
        :param sk: signing key
        :param messages_vector: message vector
        :param k_prime: index defining number of delegatable attributes  in update key uk

        :return: signature for the commitment and related opening information along with update key
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (pp_acc_G1, pp_acc_G2) = param_acc

        commitment_vector = []
        monypol_vector = []
        commit_2_vector = []

        # encode all  messagse sets of the vector as a list of vector commitments
        for mess in messages_vector:
            commitment, monypol = self.encode(pp_sign, mess)
            commitment_vector.append(commitment)
            monypol_vector.append(monypol)
            commit_2_vector.append(order.random()*g_1)
        # compute the unique identifier
        # ID_pk_u = order.random()
        # commit_2_vector = [ID_pk_u * g_1]

        # pick randomness y
        y = order.random()
        y_inv = y.mod_inverse(order)
        # compute sign -> sigma = (Z, Y, hat Ym T)
        list_Z = [sk["x_i"][i+1] * commitment_vector[i] + sk["x_i_prime"][i+1] * commit_2_vector[i] for i in range(len(commitment_vector))]
        temp_point = ec_sum(list_Z)
        Z = y_inv * temp_point
        Y = y * g_1
        Y_hat = y * g_2
        T = sk["x_i"][0] * Y + sk["x"] * pk_u
        sigma = (Z, Y, Y_hat, T)

        # compute blind commitments and send them to RA
        t = order.random()
        T_usign = t * g_1
        com_usign = {}
        usign_2_2 = {}
        # len(sk["x_i"]) = l + 1
        for item in range(len(messages_vector)+1, len(sk["x_i"])):
            usign_2_2[item] = ((sk["x_i_prime"][item] * y_inv)%order) * g_1
            com_usign[item] = T_usign + usign_2_2[item]

        # unblind com_usign
        usign_2_1 = {}
        #check if the update key is requested then compute update key using k_prime, otherwise compute signature without it
        if k_prime != None:
            if k_prime > len(messages_vector):
                # usign_1
                usign_1,usign_2_2_k,usign_2_1_k = {},{},{}
                for item in range(len(messages_vector) + 1, k_prime + 1):
                    UK = {}
                    for k,v in subset_indics.items():
                        UK[v] = ((sk["x_i"][item] * y_inv)%order) * lagrange_basic_G_list[v]
                    usign_1[item] = UK
                    usign_2_2_k[item] = usign_2_2[item]
                update_key = {
                    'usign_1':usign_1,
                    'usign_2':[usign_2_1_k,usign_2_2_k]
                }
                return (sigma, update_key, commitment_vector, monypol_vector, commit_2_vector)
            else:
                print("not a good index, k_prime index should be greater  than message length")
        else:
            return (sigma, commitment_vector, monypol_vector,commit_2_vector)

    def Random_All(self, pp_sign, vk, pk_u, commitment_vector, monypol_vector, commit_2_vector, sigma, mu, upsilon, B=False, update_key=None):
        """
          Change representation of the signature message pair to a new commitment vector and user public key.

        :param pp_sign: signature public parameters
        :param vk: verification key
        :param pk_u: user public key
        :param commitment_vector: commitment vector
        :param opening_vector: opening information vector related to commitment vector
        :param sigma: signature
        :param mu: randomness is used to randomize commitment vector and signature accordingly
        :param psi: randomness is used to randomize commitment vector and signature accordingly
        :param B: a falge to determine if it needs to randomize upda key as well or not
        :param update_key: update key, it can be none in the case that no need for randomization

        :return: a randomization of message-signature pair
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        # pick randomness
        delta = order.random()

        # randomize Commitment and opening vectors and user public key with randomness mu, chi
        rndmz_commitment_vector, rndmz_monypol_vector = self.rndmz_commit(commitment_vector, monypol_vector, mu)
        rndmz_commit_2_vector = self.rndmz_commit_2(commit_2_vector,mu)
        rndmz_pk_u = self.rndmz_pk(pp_sign, pk_u, upsilon, delta)

        # adapt the signiture for the randomized coomitment vector and PK_u_prime
        (Z, Y, Y_hat, T) = sigma
        Z_prime = (mu * upsilon.mod_inverse(order)) * Z
        Y_prime = upsilon * Y
        Y_hat_prime = upsilon * Y_hat
        T_prime = upsilon * (T + delta * vk['x'][0])
        sigma_prime = (Z_prime, Y_prime, Y_hat_prime, T_prime)
        x = 0
        # Check if it is allowed to randomize update_key for further delegation, if yes then randomize it
        if B == True and update_key != None:
            usign = update_key
            usign_1_prime,usign_2_1_prime,usign_2_2_prime = {},{},{}
            for key in usign['usign_1']:
                update_keylist = usign['usign_1'].get(key)
                mainop = {}
                for k,v in update_keylist.items():
                    mainop[k] = (mu * upsilon.mod_inverse(order)) * v
                usign_1_prime[key] = mainop
                usign_2_2_prime[key] = (mu * upsilon.mod_inverse(order)) * usign['usign_2'][1].get(key)
                x = x+1
            rndmz_update_key = {
                'usign_1':usign_1_prime,
                'usign_2':[usign_2_1_prime,usign_2_2_prime]
            }
            return (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta)
        else:
            return (sigma_prime, rndmz_commitment_vector, rndmz_monypol_vector, rndmz_commit_2_vector, rndmz_pk_u, delta)

    def Delegate(self, pp_sign, param_acc, message_l, index_l, pk_l, sigma, commitment_vector, monypol_vector, commit_2_vector, update_key, subset_indics_L, mu=1, k_prime_double = None):
        """
         Update the signature for a new commitment vector including 𝐶_L for message_l using update_key

        :param pp_sign: signature public parameters
        :param message_l: message set at index l that will be added in message vector
        :param index_l: index l denotes the next position of message vector that needs to be fixed
        :param sigma: signature
        :param commitment_vector: signed commitment vector
        :param opening_vector:opening information related to commitment vector
        :param update_key: updates key can add more messages and commitment into signature message pair
        :param mu: randomness

        :return: a new singitre including the message set l
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (pp_acc_G1, pp_acc_G2) = param_acc
        usign = update_key
        Z, Y, Y_hat, T = sigma
        commitment_L, monypol_L = self.encode(pp_sign, message_l,subset_indics_L)
        rndmz_commitment_L = mu * commitment_L
        rndmz_monypol_L = []

        
        # compute the unique identifier
        ID_pk_l = order.random()
        com_L_2 = ID_pk_l * g_1
        rndmz_com_L_2 = mu * com_L_2


        # add the commitment CL for index L into the signature, the update commitment vector and opening for this new commitment
        if (index_l in usign['usign_1']):
            set_l = convert_mess_to_bn(message_l)
            usign_L_1 = usign['usign_1'].get(index_l)
            usign_L_2 = [[],usign['usign_2'][1].get(index_l)]
            points_uk_i = []
            for k,v in subset_indics_L.items():
                points_uk_i.append(set_l[k]* usign_L_1[v])
            points_uk = ec_sum(points_uk_i)
            V = points_uk + ID_pk_l * usign_L_2[1]
            Z_tilde = Z + V
            sigma_tilde = (Z_tilde, Y, Y_hat, T)
            commitment_vector.append(rndmz_commitment_L)
            monypol_vector.append(rndmz_monypol_L)
            commit_2_vector.append(rndmz_com_L_2)
            if k_prime_double is None:
                return (sigma_tilde, commitment_L, monypol_L, commitment_vector, monypol_vector, commit_2_vector)
            else:
                usign_prime = {
                    'usign_1':[],
                    'usign_2':[]
                }
                for i in range(index_l+1,k_prime_double+1):
                    usign_prime["usign_1"].append(usign['usign_1'].get(i))
                    usign_prime["usign_2"].append([[],usign['usign_2'][1].get(i)])
                    return (sigma_tilde, usign_prime, commitment_L, monypol_L, commitment_vector, monypol_vector, commit_2_vector)
        else:
            raise("index_l is the out of scope")


    def send_convert_sig(self , vk, sk_u, sigma):
        """
        create a temporary (orphan) signature for use in the convert signature algorithm.

        :param vk: verification key
        :param sk_u: user secre key
        :param sigma: a signature
        :return: a tempretory (orpha) signature for convert signature algo
        """
        (Z, Y, Y_hat, T) = sigma
        # update component T of signature to remove the old key
        T_new = T + ((sk_u *vk['x'][0]).neg())
        sigma_orpha = (Z, Y, Y_hat, T_new)
        return sigma_orpha

    def receive_convert_sig(self, vk, sk_r, sigma_orpha):
        """
        On input a temporary (orphan) signature and returns a new signature for the new public key.

        :param vk: verification key
        :param sk_r: secret key if a new user
        :param sigma_orpha: a temporary (orphan) signature

        :return: a new signature for the new public key
        """
        (Z, Y, Y_hat, T) = sigma_orpha
        # update component T of signature with a new key
        T_new = T + (sk_r * vk['x'][0] )
        # output sigma_prime as new sign valid for the new key
        sigma_prime = (Z, Y, Y_hat, T_new)
        return sigma_prime
    
    def uk_verify(self, pp_sign, param_acc, vk, update_key, sigma):
        """
        checks if the uk is valid

        :param pp_sign: signature public parameters
        :param vk: verification key
        :param pk_u: user public key
        :param commitment_vector: signed commitment vector
        :param sigma: signature for commitment vector

        :return: check if signature is valid: 0/1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (pp_acc_G1, pp_acc_G2) = param_acc
        (Z, Y, Y_hat, T) = sigma
        usign = update_key
        # usign_i_def
        usign_1_list,usign_2_1_list,usign_2_2_list = [],[],[]
        vk_x_list,vk_x_prime_list = [],[]
        lagrange_group_list = []
        flag = True

        for key in usign['usign_1']:
            # usign_1_get
            update_keylist = usign['usign_1'].get(key)
            for k,v in update_keylist.items():
                usign_1_list.append(v)
                if flag:
                    lagrange_group_list.append(lagrange_basic_G_list[k])
            flag = False
            vk_x_list.append(vk["x_i"][key])
            # usign_2_get
            vk_x_prime_list.append(vk["x_i_prime"][key])
            usign_2_2_list.append(usign['usign_2'][1].get(key))
 
        # usign_eq_1
        left_side_eq_1 = group.pair(ec_sum(lagrange_group_list),ec_sum(vk_x_list))
        right_side_eq_1 = group.pair(ec_sum(usign_1_list),Y_hat)

        # usign_eq_3
        left_side_eq_3 = group.pair(g_1,ec_sum(vk_x_prime_list))
        right_side_eq_3 = group.pair(ec_sum(usign_2_2_list),Y_hat)

        return (left_side_eq_1 == right_side_eq_1) and (left_side_eq_3 == right_side_eq_3)

    def verify(self, pp_sign, vk, pk_u, commitment_vector, commit_2_vector, sigma):
        """
        checks if the signature is valid

        :param pp_sign: signature public parameters
        :param vk: verification key
        :param pk_u: user public key
        :param commitment_vector: signed commitment vector
        :param sigma: signature for commitment vector

        :return: check if signature is valid: 0/1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_sign
        (Z, Y, Y_hat, T) = sigma

        # statment 1
        right_side = group.pair(Z, Y_hat)

        pairing_op_1 = [group.pair(commitment_vector[j], vk['x_i'][j+1]) for j in range(len(commitment_vector))]
        pairing_op_2 = [group.pair(commit_2_vector[j], vk['x_i_prime'][j+1]) for j in range(len(commit_2_vector))]

        # statment 2
        left_side = product_GT(pairing_op_1+pairing_op_2)

        return (group.pair(Y, g_2) == group.pair(g_1, Y_hat)) and (group.pair(T, g_2) == group.pair(Y, vk['x_i'][0]) * group.pair(pk_u, vk['x'][1])) and (right_side == left_side)
