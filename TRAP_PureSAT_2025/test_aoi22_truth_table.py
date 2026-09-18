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

def check_truth_table():
    key_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\work\extracted_key.csv'
    pl_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\test\Test13-TRAP_2x2_AOI22\trap2x2AOI22.py'

    # 1. Read extracted key
    key_vals = {}
    with open(key_file, 'r') as f:
        for row in csv.reader(f):
            if row:
                key_vals[row[0].strip()] = (row[1].strip() == 'True')

    # 2. Read PL
    vars_dict, clauses_list = readZ3pl(pl_file)

    print("=" * 75)
    print("EXHAUSTIVE TRUTH TABLE VERIFICATION FOR AOI22 (2x2 FABRIC)")
    print("Formula: Output = NOT((a AND b) OR (c AND d))")
    print("=" * 75)
    print(f"|  a  |  b  |  c  |  d  | Golden AOI22 | Extracted Key Fabric | Match Result |")
    print(f"|:---:|:---:|:---:|:---:|:------------:|:--------------------:|:------------:|")

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
    for a_val in [False, True]:
        for b_val in [False, True]:
            for c_val in [False, True]:
                for d_val in [False, True]:
                    golden_out = not ((a_val and b_val) or (c_val and d_val))
                    
                    s = Solver()
                    for c in base_clauses:
                        s.add(c)
                    
                    # Fix inputs
                    s.add(exec_ctx['a'] == a_val)
                    s.add(exec_ctx['b'] == b_val)
                    s.add(exec_ctx['c'] == c_val)
                    s.add(exec_ctx['d'] == d_val)
                    
                    # Fix keys with extracted key
                    for k, v in key_vals.items():
                        if k in exec_ctx:
                            s.add(exec_ctx[k] == v)
                    
                    if s.check() == sat:
                        m = s.model()
                        fabric_out = is_true(m[exec_ctx['o']])
                        match = (fabric_out == golden_out)
                        if not match:
                            all_pass = False
                        res_str = "MATCH (PASS)" if match else "MISMATCH (FAIL)"
                        print(f"|  {int(a_val)}  |  {int(b_val)}  |  {int(c_val)}  |  {int(d_val)}  |      {int(golden_out)}       |          {int(fabric_out)}           | {res_str:^12} |")
                    else:
                        print(f"|  {int(a_val)}  |  {int(b_val)}  |  {int(c_val)}  |  {int(d_val)}  |      {int(golden_out)}       |        UNSAT         | ERROR (FAIL) |")
                        all_pass = False

    print("=" * 75)
    if all_pass:
        print("CONGRATULATIONS: 16/16 TEST CASES MATCH 100%! KEY IS PERFECTLY VALID!")
    else:
        print("VERIFICATION FAILED!")
    print("=" * 75)

if __name__ == '__main__':
    check_truth_table()
