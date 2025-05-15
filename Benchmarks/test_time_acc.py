import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.Acc import Accumulator
from core.aSVC import VectorCommitment
from core.util import *
import timeit


len_F_x = 5
len_non_list = 9
number_of_tests = 200

def setup_module():
    print("__________Setup__test accumulator___________")
    global acc_scheme, pp, pp_ac
    vc_scheme = VectorCommitment(max_cardinal =10)
    # create public parameters for VC schemes
    pp_ac, alpha = vc_scheme.setup()
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_ac
    # create acc_scheme
    acc_scheme = Accumulator(group, max_cardinal =10)
    # create public parameters for acc_scheme
    pp, alpha = acc_scheme.setup()





if __name__== "__main__" :
    setup_module()
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group, roots_of_unity, basic_coeffs, lagrange_basic_G_list) = pp_ac
    point = order.random()
    points_x = []
    for i in range(len_F_x):
        points_x.append(order.random())
    non_list_points = []
    for i in range(len_non_list):
        non_list_points.append(order.random())
    F_x = poly_from_roots(points_x, order)
    non_list = poly_from_roots(non_list_points, order)
    # create Acc for F_x,non_list
    Acc = acc_scheme.AccCom(pp, F_x, G2_Element=True)
    add_time = timeit.timeit('acc_scheme.AccAdd(Acc, point)', globals=globals(), number=number_of_tests)
    #print(f"Average time for issue_time: {add_time / number_of_tests:.6f} seconds")
    print(f"Average time for AccAdd_time: {add_time:.6f} seconds")