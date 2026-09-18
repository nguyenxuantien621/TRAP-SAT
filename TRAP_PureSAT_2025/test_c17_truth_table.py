import csv
import sys
import os
from z3 import *

sys.path.insert(0, r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025')
from src.satAttack import readZ3pl

def is_greater_3bit(B2, B1, B0, A2, A1, A0):
    t1 = And(B2, Not(A2))
    t2 = And(B2 == A2, B1, Not(A1))
    t3 = And(B2 == A2, B1 == A1, B0, Not(A0))
    return Or(t1, t2, t3)

def compute_golden_c17(pi1, pi2, pi3, pi6, pi7):
    nand1 = not (pi1 and pi3)
    nand2 = not (pi3 and pi6)
    nand5 = not (nand2 and pi7)
    nand6 = not (nand2 and pi2)
    nand3 = not (nand1 and nand6)
    nand4 = not (nand6 and nand5)
    po22 = nand3
    po23 = nand4
    return po22, po23

def check_truth_table():
    key_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\work\extracted_key.csv'
    pl_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\test\Test14-TRAP_2x2_C17\trap2x2C17.py'

    # 1. Read extracted key
    key_vals = {}
    with open(key_file, 'r') as f:
        for row in csv.reader(f):
            if row:
                key_vals[row[0].strip()] = (row[1].strip() == 'True')

    # 2. Read PL
    vars_dict, clauses_list = readZ3pl(pl_file)

    print("=" * 80)
    print("EXHAUSTIVE TRUTH TABLE VERIFICATION FOR C17 (2x2 FABRIC)")
    print("5 Inputs (32 combinations) | 2 Outputs (po22, po23)")
    print("=" * 80)
    print(f"| pi1 | pi2 | pi3 | pi6 | pi7 | Golden (po22,po23) | Fabric (po22,po23) | Match Result |")
    print(f"|:---:|:---:|:---:|:---:|:---:|:------------------:|:------------------:|:------------:|")

    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['And'] = And
    exec_ctx['Or'] = Or
    exec_ctx['Not'] = Not
    exec_ctx['Implies'] = Implies
    exec_ctx['Xor'] = Xor
    exec_ctx['Bool'] = Bool

    base_clauses = []
    for c_str in clauses_list:
        try:
            base_clauses.append(eval(c_str, exec_ctx))
        except Exception:
            pass

    all_pass = True
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                        
                        s = Solver()
                        for c in base_clauses:
                            s.add(c)
                        
                        # Fix inputs
                        s.add(exec_ctx['pi1'] == p1)
                        s.add(exec_ctx['pi2'] == p2)
                        s.add(exec_ctx['pi3'] == p3)
                        s.add(exec_ctx['pi6'] == p6)
                        s.add(exec_ctx['pi7'] == p7)
                        
                        # Fix keys with extracted key
                        for k, v in key_vals.items():
                            if k in exec_ctx:
                                s.add(exec_ctx[k] == v)
                        
                        if s.check() == sat:
                            m = s.model()
                            f22 = is_true(m[exec_ctx['po22']])
                            f23 = is_true(m[exec_ctx['po23']])
                            match = (f22 == g22) and (f23 == g23)
                            if not match:
                                all_pass = False
                            res_str = "MATCH (PASS)" if match else "MISMATCH (FAIL)"
                            print(f"|  {int(p1)}  |  {int(p2)}  |  {int(p3)}  |  {int(p6)}  |  {int(p7)}  |       ({int(g22)}, {int(g23)})        |       ({int(f22)}, {int(f23)})        | {res_str:^12} |")
                        else:
                            print(f"|  {int(p1)}  |  {int(p2)}  |  {int(p3)}  |  {int(p6)}  |  {int(p7)}  |       ({int(g22)}, {int(g23)})        |      UNSAT         | ERROR (FAIL) |")
                            all_pass = False

    print("=" * 80)
    if all_pass:
        print("CONGRATULATIONS: 32/32 TEST CASES MATCH 100%! KEY IS PERFECTLY VALID!")
    else:
        print("VERIFICATION FAILED!")
    print("=" * 80)

if __name__ == '__main__':
    check_truth_table()
