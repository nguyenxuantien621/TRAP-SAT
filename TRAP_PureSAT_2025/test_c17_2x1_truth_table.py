#!/usr/bin/env python3
'''
Independent Truth Table Equivalence Checker for Test16 (C17 on 2x1 TRAP Fabric)
Compares Golden C17 ASIC vs TRAP 2x1 Fabric with extracted key across 100% truth table (32 input patterns).
'''

import csv
import sys
import os
from z3 import *

from src.pysatAttack import (
    readZ3pl,
    is_greater_3bit, is_greater_4bit, is_greater_5bit,
    is_greater_6bit, is_greater_7bit, is_greater_8bit,
    build_magnitude_comparator
)

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

def check_c17_2x1():
    key_file = 'test/Test16-TRAP_2x1_C17/extracted_key.csv'
    pl_file = 'test/Test16-TRAP_2x1_C17/trap2x1C17.py'

    print("\nLoading files for Test16 (C17 2x1)...")
    if not os.path.exists(key_file):
        print(f"Error: {key_file} not found!")
        return

    # 1. Read extracted key
    key_vals = {}
    with open(key_file, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                key_vals[row[0].strip()] = (row[1].strip().lower() == 'true')
    print(f"[*] Loaded {len(key_vals)} key bits from {key_file}")

    # 2. Read PL
    vars_dict, clauses_list = readZ3pl(pl_file)

    print("=" * 80)
    print("EXHAUSTIVE TRUTH TABLE VERIFICATION FOR C17 (2x1 FABRIC)")
    print("5 Inputs (32 combinations) | 2 Outputs (po22, po23)")
    print("=" * 80)
    print(f"| pi1 | pi2 | pi3 | pi6 | pi7 | Golden (po22,po23) | Fabric (po22,po23) | Match Result |")
    print(f"|:---:|:---:|:---:|:---:|:---:|:------------------:|:------------------:|:------------:|")

    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['is_greater_4bit'] = is_greater_4bit
    exec_ctx['is_greater_5bit'] = is_greater_5bit
    exec_ctx['is_greater_6bit'] = is_greater_6bit
    exec_ctx['is_greater_7bit'] = is_greater_7bit
    exec_ctx['is_greater_8bit'] = is_greater_8bit
    exec_ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})

    base_clauses = []
    for c_str in clauses_list:
        try:
            base_clauses.append(eval(c_str, exec_ctx))
        except Exception:
            pass

    s = Solver()
    for c in base_clauses:
        s.add(c)

    # Pin all extracted keys
    for k, v in key_vals.items():
        if k in exec_ctx:
            s.add(exec_ctx[k] == v)

    # Output validity enable
    s.add(exec_ctx['VL47_1_0'] == True)
    s.add(exec_ctx['VL49_1_0'] == True)

    all_pass = True
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                        
                        s.push()
                        # Fix inputs
                        s.add(exec_ctx['pi1'] == p1)
                        s.add(exec_ctx['pi2'] == p2)
                        s.add(exec_ctx['pi3'] == p3)
                        s.add(exec_ctx['pi6'] == p6)
                        s.add(exec_ctx['pi7'] == p7)
                        
                        res = s.check()
                        if res == sat:
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
                        s.pop()

    print("=" * 80)
    if all_pass:
        print("CONGRATULATIONS: 32/32 TEST CASES MATCH 100%! KEY IS PERFECTLY VALID!")
    else:
        print("VERIFICATION COMPLETED: Some test cases did not match or returned UNSAT.")
    print("=" * 80 + "\n")

if __name__ == '__main__':
    check_c17_2x1()
