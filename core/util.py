"""
Some common and basic tools are used in the project, such as converting messages (attributes) to the format that 
can be used in the bilinear pairing, EQ relations, and (trapdoor) Pederson commitment, 

UPDATE: Roots_of_unity, Lagrange Polynomial, Polynomial Tools, Set Tools
@Author: Min Xie
"""

from termcolor import colored
from coconut.scheme import *
from coconut.utils import *
import numpy as np
import sympy
import galois
import random

# ==================================================
# Setup parameters:
# ==================================================

## this class generates bilinear pairing BG

class GenParameters:

    def __init__(self):
        self.e = BpGroup()
        self.g1, self. g2 = self.e.gen1(), self.e.gen2()
        self.Order = self.e.order()

    # getter methods
    def get_e(self):
        return self.e

    def get_Order(self):
        return self.Order

    def get_g1(self):
        return self.g1

    def get_g2(self):
        return self.g2


# ==================================================
# others
# ==================================================

def ec_sum(list):
    """ sum EC points list """
    ret = list[0]
    for i in range(1, len(list)):
        ret = ret + list[i]
    return ret

def ec_sum_with_coeffs(bases,powers):
    """ sum EC points list with """
    ret = bases[0].mul(powers[0])
    for i in range(1, len(bases)):
        ret = ret + bases[i].mul(powers[i])
    return ret

def product_GT(list_GT):
    """ pairing product equations of a list """
    ret_GT = list_GT[0]
    for i in range(1, len(list_GT)):
        ret_GT = ret_GT * (list_GT[i])
    return ret_GT

# modular math
def mod_inv(x, p):
	assert gcd(x, p) == 1, "Divisor %d not coprime to modulus %d" % (x, p)
	z, a = (x % p), 1
	while z != 1:
		q = - (p // z)
		z, a = (p + q * z), (q * a) % p
	return a

def gcd(a, b):
	while b:
		a, b = b, a % b
	return a

def extended_gcd(a, b):
    """
    Perform the Extended Euclidean Algorithm on Bn objects a and b.

    Parameters:
    - a, b: Bn objects.

    Returns:
    - gcd: The greatest common divisor of a and b.
    - x, y: The Bézout coefficients for a and b.
    """
    # if a == Bn(0):
    #     return (b, Bn(0), Bn(1))
    # else:
    #     g, x, y = extended_gcd(b % a, a)
    #     return (g, y - (b // a) * x, x)
    if b == Bn(0):
        return (a, Bn(1), Bn(0))
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (gcd, x, y)

# ==================================================
# Attribute Representation:
# ==================================================
def eq_relation(message_vector, mu):
    message_representive = []
    if isinstance(message_vector[0], list):
        for message in message_vector:
             message_representive.append([message[i] * mu  for i in range(len(message))])
    elif isinstance(message_vector, list):
        message_representive = [message * mu for message in message_vector]
    else:
        print("not correct format, insert a list of group elements or a list of list")
    return message_representive

def eq_dh_relation(dh_message_vector, mu, opsilon):
    dh_message_representive = [[item[0] * mu, item[1] * opsilon] for item in dh_message_vector]
    return dh_message_representive


def convert_mess_to_groups(message_vector):
    """
    :param: get a vector of strings or vector of vector strings as message_vector
    :return: return a vector of group elements in G1
    """
    message_group_vector = []
    if type(message_vector[0])== str:
        message_group_vector = [BpGroup().hashG1(message.encode()) for message in message_vector]
    else:
        for message in message_vector:
            temp = [BpGroup().hashG1(message[i].encode()) for i in range(len(message))]
            message_group_vector.append(temp)

    return message_group_vector

def convert_mess_to_bn(messages):
    if type(messages)==str:
        Conver_message = Bn.from_binary(str.encode(messages))
        # print(colored('insert all messages as string'+ len(Conver_message), 'blue'))
    elif isinstance(messages, set) or isinstance(messages, list):
        try:
            Conver_message = list(map(lambda item: Bn.from_binary(str.encode(item)), messages))
            # print(colored('insert all messages as list'+ len(Conver_message), 'pink'))
        except:
            print(colored('insert all messages as string', 'green'))
    else:
        print(colored('message type is not correct', 'green'))

    return Conver_message



# ==================================================
# Trapdoor (pedersen) commitment
# ==================================================

def pedersen_setup(group):
   """ generate an pedersen parameters with a Trapdoor d (only used in POK) """
   g = group.gen1()
   o = group.order()
   group =group
   d = o.random()
   h = d * g
   trapdoor = d
   pp_pedersen = (group, g, o, h)
   return (pp_pedersen, trapdoor)


def pedersen_committ(pp_pedersen, m):
    """ commit/encrypts the values of a message (g^m) """
    (G, g, o, h) = pp_pedersen
    r = o.random()
    if type(m) is Bn:
        pedersen_commit = r * h + m * g
    else:
        pedersen_commit = r * h + m
    pedersen_open = (r, m)
    return (pedersen_commit, pedersen_open)

def pedersen_dec(pp_pedersen, pedersen_open, pedersen_commit):
    """ decrypts/decommit the message """
    (G, g, o, h) = pp_pedersen
    (r, m) = pedersen_open
    if type(m) == Bn:
        c2 = r * h + m * g
    else:
        c2 = r * h + m
    return c2== pedersen_commit


# ==================================================
# Roots_of_unity
# ==================================================
#  complex
def generate_roots_of_unity(n):
    # the range of k is [0,n-1]
    k = np.arange(n)
    # generate roots
    roots = np.exp(2j * np.pi * k / n)
    return roots


#  integer
def generate_integer_roots_of_unity(prime, n):
    # 找到模prime的一个原根
    primitive_root = Bn.from_num(sympy.primitive_root(int(prime)))
    # 生成n个单位根
    roots_of_unity = [primitive_root.mod_pow(i, prime) for i in range(n)]
    return roots_of_unity

# ==================================================
# Lagrange Polynomial
# ==================================================

def compute_basis_polynomial_coefficients(idx, points, modulus):
    """
    Compute the coefficients of the Lagrange basis polynomial for a given index.
    
    Inputs:
    - idx: Index of the current basis polynomial being calculated.
    - points: List of tuples (x, y), with x and y as Bn objects representing points in the field.
    - modulus: The prime modulus as a Bn object defining the finite field.
    
    Output:
    - Coefficients of the idx-th basis polynomial as a list of Bn objects.
    """
    n = len(points)
    coefficients = [Bn(1)]
    
    for i in range(n):
        if i != idx:
            xi, xj = points[idx], points[i]
            # Construct (x - xj) for the current basis polynomial
            current_poly = [modulus - xj, Bn(1)]  # Polynomial: -xj + x
            
            # Compute the denominator (xi - xj)^(-1) mod modulus for the basis polynomial
            denom_inv = (xi - xj).mod_inverse(modulus)
            
            # Update the coefficients of the current basis polynomial
            updated_coeffs = []
            for coeff in current_poly:
                updated_coeffs.append((coeff * denom_inv) % modulus)
            
            # Expand the basis polynomial by multiplying the current term
            new_coefficients = [Bn(0)] * (len(coefficients) + len(updated_coeffs) - 1)
            for j, coeff_j in enumerate(coefficients):
                for k, coeff_k in enumerate(updated_coeffs):
                    new_coefficients[j + k] += coeff_j * coeff_k
                    new_coefficients[j + k] %= modulus
            coefficients = new_coefficients
    
    return coefficients

def lagrange_basic_interpolation(points, modulus):
    """
    Performs Lagrange interpolation based on given points and modulus.
    
    Inputs:
    - points: List of tuples (x, y), with x and y as Bn objects representing points in the field.
    - modulus: The prime modulus as a Bn object defining the finite field.
    
    Outputs:
    - A tuple:
      1. Interpolated polynomial coefficients as a list of Bn objects.
      2. A list of lists, each containing the coefficients of a Lagrange basis polynomial as Bn objects.
    """
    n = len(points)
    # final_coefficients = [Bn(0)] * n
    all_basis_coefficients = []

    for i in range(n):
        basis_coefficients = compute_basis_polynomial_coefficients(i, points, modulus)
        all_basis_coefficients.append(basis_coefficients)
        
        # Multiply basis polynomial by yi and accumulate
        # yi = points[i][1]
        # for j in range(len(basis_coefficients)):
        #     final_coefficients[j] = (final_coefficients[j] + basis_coefficients[j] * yi) % modulus

    # Adjust the size of the final_coefficients to match the degree
    # final_coefficients += [Bn(0)] * (n - len(final_coefficients))
    
    # return final_coefficients, all_basis_coefficients
    return all_basis_coefficients

def lagrange_interpolation(lagrange_basic,points,modulus):
    n = len(lagrange_basic[0])
    final_coefficients = [Bn(0)] * n
    for i in range(len(points)):        
        # Multiply basis polynomial by yi and accumulate
        yi = points[i]
        for j in range(len(lagrange_basic[i])):
            final_coefficients[j] = (final_coefficients[j] + lagrange_basic[i][j] * yi) % modulus
            
    # Adjust the size of the final_coefficients to match the degree
    final_coefficients += [Bn(0)] * (n - len(final_coefficients))
    
    return final_coefficients

from petlib.bn import Bn

# ==================================================
# Polynomial Tools
# ==================================================

def polynomial_with_roots(roots, p):
    """
    Efficiently generate a monic polynomial given its roots, under modulus p,
    using Horner's method.

    Parameters:
    - roots: List of Bn objects representing the roots of the polynomial.
    - p: A Bn object representing the modulus.

    Returns:
    - A list of Bn objects representing the coefficients of the polynomial,
      ordered from the constant term to the highest-degree term.
    """
    # Initialize the polynomial as p(x) = 1 (the highest degree term for a monic polynomial)
    polynomial = [Bn(1)]

    # Construct the polynomial using Horner's method
    for root in reversed(roots):
        # The new polynomial will have one more degree than the current
        new_polynomial = [Bn(0)] * (len(polynomial) + 1)

        # Update the coefficients starting from the highest degree
        for i in range(len(polynomial)):
            new_polynomial[i + 1] = polynomial[i]
        
        # Apply the root subtraction and modulus for each coefficient
        for i in range(len(new_polynomial) - 1):
            new_polynomial[i] = (new_polynomial[i] - root * new_polynomial[i + 1]) % p

        polynomial = new_polynomial

    return polynomial

def multiply_polynomial_by_binomial(coeffs, r, modulus):
    """
    Multiplies a polynomial F(x) by a binomial (x + r) under a given modulus.

    Parameters:
    - coeffs: List of Bn objects representing the coefficients of F(x), from constant term to highest degree.
    - r: A Bn object representing the root r_{n+1}.
    - modulus: A Bn object representing the modulus.

    Returns:
    - List of Bn objects representing the coefficients of F'(x), from constant term to highest degree.
    """
    # Initialize the result polynomial coefficients array with zeros, one degree higher than the input polynomial.
    result_coeffs = [Bn(0)] * (len(coeffs) + 1)
    
    # Apply polynomial multiplication under modulus
    for i in range(len(coeffs)):
        # Compute the new coefficient for x^i * r (contributes to the same degree)
        result_coeffs[i] = (result_coeffs[i] + coeffs[i] * r) % modulus
        # Compute the new coefficient for x^i * x (contributes to the degree i+1)
        result_coeffs[i + 1] = (result_coeffs[i + 1] + coeffs[i]) % modulus
    
    return result_coeffs

def poly_from_roots(roots, modulus):
    """
    Compute the coefficients of a polynomial given its roots, using (x + r) factors modulo a given modulus.

    Parameters:
    roots -- A list of polynomial roots (each of type Bn).
    modulus -- The modulus for coefficient arithmetic (type Bn).

    Returns:
    A list of Bn coefficients representing the polynomial, from constant term to highest degree.
    """
    coeffs = [Bn(1)]  # Initial polynomial is 1

    # Multiply (x + r) for each root
    for r in roots:
        # Temporary list to store intermediate coefficients
        temp_coeffs = [Bn(0) for _ in range(len(coeffs) + 1)]

        for i in range(len(coeffs)):
            # Multiply by r (for x term)
            temp_coeffs[i] = (temp_coeffs[i] + coeffs[i] * r) % modulus
            # Multiply by 1 (for constant term)
            temp_coeffs[i + 1] = (temp_coeffs[i + 1] + coeffs[i]) % modulus

        coeffs = temp_coeffs

    return coeffs

def poly_div_mod(dividend, divisor, modulus):
    """
    Performs polynomial division (dividend / divisor) under a given modulus.

    Parameters:
    - dividend: List of Bn objects for the dividend polynomial coefficients, ordered from lowest to highest degree.
    - divisor: List of Bn objects for the divisor polynomial coefficients, ordered from lowest to highest degree.
    - modulus: A Bn object representing the modulus under which the division is performed.

    Returns:
    - quotient: List of Bn objects for the quotient polynomial coefficients, ordered from lowest to highest degree.
    - remainder: List of Bn objects for the remainder polynomial coefficients, ordered from lowest to highest degree.
    """

    # Initialize quotient and remainder
    quotient = [Bn(0)] * (len(dividend) - len(divisor) + 1)
    remainder = dividend.copy()

    # Ensure divisor is non-zero
    if len(divisor) == 0 or all(c == Bn(0) for c in divisor):
        raise ValueError("Divisor polynomial cannot be zero.")

    # Long division algorithm
    divisor_degree = len(divisor) - 1
    divisor_lead_inv = divisor[-1].mod_inverse(modulus)

    for i in range(len(dividend) - len(divisor), -1, -1):
        # Calculate current quotient coefficient
        q_coeff = remainder[i + divisor_degree] * divisor_lead_inv % modulus
        quotient[i] = q_coeff

        # Subtract the current quotient times the divisor from the remainder
        for j in range(divisor_degree + 1):
            remainder[i + j] -= q_coeff * divisor[j] % modulus
            remainder[i + j] = remainder[i + j].mod(modulus)

    # Trim leading zero coefficients from remainder
    while len(remainder) > 0 and remainder[-1] == Bn(0):
        remainder.pop()

    # Trim leading zero coefficients from quotient
    while len(quotient) > 1 and quotient[-1] == Bn(0):
        quotient.pop()

    return quotient, remainder

def poly_sub(poly1, poly2, modulus):
    """
    Performs polynomial subtraction (poly1 - poly2) under a given modulus.

    Parameters:
    - poly1: List of Bn objects for the first polynomial coefficients, ordered from lowest to highest degree.
    - poly2: List of Bn objects for the second polynomial coefficients, ordered from lowest to highest degree.
    - modulus: A Bn object representing the modulus under which the subtraction is performed.

    Returns:
    - A list of Bn objects representing the coefficients of the result polynomial,
      ordered from lowest to highest degree.
    """
    # Ensure the result polynomial has enough space for the highest degree of the input polynomials
    max_len = max(len(poly1), len(poly2))
    result = [Bn(0) for _ in range(max_len)]

    # Fill in the coefficients for poly1
    for i in range(len(poly1)):
        result[i] = poly1[i]

    # Subtract the coefficients for poly2
    for i in range(len(poly2)):
        if i < len(poly1):
            result[i] = (poly1[i] - poly2[i]) % modulus
        else:
            # If poly2 is longer than poly1, handle negative coefficients properly
            result[i] = (modulus - poly2[i]) % modulus

    # Remove trailing zeros
    while len(result) > 1 and result[-1] == Bn(0):
        result.pop()

    return result

def evaluate_polynomial(coefficients, x_value, modulus):
    """
    Evaluate a polynomial at a given point x_value under modulus p using Horner's Rule.

    Parameters:
    - coefficients: List of Bn objects representing the polynomial coefficients, ordered from constant term to highest degree.
    - x_value: A Bn object representing the point at which to evaluate the polynomial.
    - modulus: A Bn object representing the modulus under which the evaluation is performed.

    Returns:
    - The value of the polynomial at x_value as a Bn object.
    """
    # Initialize the result to 0
    result = Bn(0)

    # Iterate through coefficients from highest degree to constant term
    for coeff in reversed(coefficients):
        result = (result * x_value + coeff) % modulus

    return result

def get_disjoint_points(order, len_F_x, len_non_list):
    """
    Generate two disjoint lists of random Bn elements modulo a given order.

    Parameters:
    - order: A Bn object representing the modulus (defines Z_p).
    - len_F_x: Number of elements to generate for the first list (points_x).
    - len_non_list: Number of disjoint elements to generate for the second list (non_list_points).

    Returns:
    - points_x: A list of Bn elements sampled uniformly from Z_p.
    - non_list_points: A list of Bn elements disjoint from points_x.
    """
    used = set()
    points_x = []
    while len(points_x) < len_F_x:
        r = Bn.from_decimal(str(random.randint(0, int(order) - 1)))
        if r not in used:
            used.add(r)
            points_x.append(r)

    non_list_points = []
    while len(non_list_points) < len_non_list:
        r = Bn.from_decimal(str(random.randint(0, int(order) - 1)))
        if r not in used:
            used.add(r)
            non_list_points.append(r)

    return points_x, non_list_points

def generate_disjoint_points(existing_points, count, order):
    """
    Generate a list of Bn elements that are disjoint from existing_points.

    Parameters:
    - existing_points: list of Bn elements (already used points)
    - count: number of disjoint points to generate
    - order: modulus (Bn), defines the field Z_p

    Returns:
    - A list of Bn elements disjoint from existing_points
    """
    existing_set = set(int(x) % int(order) for x in existing_points)
    disjoint_points = []

    while len(disjoint_points) < count:
        candidate = Bn.from_decimal(str(random.randint(0, int(order) - 1)))
        if int(candidate) not in existing_set:
            disjoint_points.append(candidate)
            existing_set.add(int(candidate))  # add to set to avoid duplicates

    return disjoint_points

# ==================================================
# Set Tools
# ==================================================

def remove_subset(sequence, subset):
    # 用于存放结果的列表
    result = []
    
    # 初始化指针
    i, j = 0, 0
    
    # 主循环：同时遍历主序列和子集
    while i < len(sequence) and j < len(subset):
        if sequence[i] < subset[j]:
            result.append(sequence[i])
            i += 1
        elif sequence[i] == subset[j]:
            # 如果当前元素在子集中，跳过它
            i += 1
            j += 1
        else:
            # 如果子集的当前元素大于主序列元素，移动子集指针
            j += 1
    
    # 添加剩余的主序列元素
    result.extend(sequence[i:])
    
    return result