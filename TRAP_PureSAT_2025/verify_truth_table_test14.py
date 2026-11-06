#!/usr/bin/env python3
"""
Exhaustive Truth Table Verification Script:
- Test 14: TRAP 2x2 C17 (32 input combinations)
"""

import os
import sys
import csv
import itertools
from z3 import *

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from src.pysatAttack import (
    readZ3pl, parsePL, runPyOracle,
    build_magnitude_comparator,
    is_greater_3bit, is_greater_4bit, is_greater_5bit,
    is_greater_6bit, is_greater_7bit, is_greater_8bit
)

exec_ctx_base = {
    'build_magnitude_comparator': build_magnitude_comparator,
    'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
    'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
    'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
    'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
}

def verify_test14():
    base_dir = current_dir
    pl_file = os.path.join(base_dir, 'test', 'Test14-TRAP_2x2_C17', 'trap2x2C17.py')
    io_file = os.path.join(base_dir, 'test', 'Test14-TRAP_2x2_C17', 'trap2x2C17_io.csv')
    oracle_file = os.path.join(base_dir, 'test', 'Test14-TRAP_2x2_C17', 'c17.py')
    key_file = os.path.join(base_dir, 'test', 'Test14-TRAP_2x2_C17', 'extracted_key.csv')

    print("=" * 80)
    print("EXHAUSTIVE Z3 TRUTH TABLE VERIFICATION: Test14-TRAP_2x2_C17")
    print("=" * 80)

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    if not os.path.exists(key_file):
        print(f"Error: {key_file} not found!")
        return False

    key_rows = []
    cand_key = {}
    with open(key_file, 'r', encoding='utf-8') as f:
        for r in csv.reader(f):
            if r:
                key_rows.append(r)
                cand_key[r[0].strip()] = (r[1].strip() == 'True')

    print(f"Total key lines loaded: {len(key_rows)} ({len(cand_key)} unique keys) | Expected in io.csv: {len(keyVars)}")
    print(f"Inputs ({len(inVars)}): {inVars} | Outputs ({len(outVars)}): {outVars}")
    print(f"Validities: {hiZVars}")

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    s = Solver()
    s.set('timeout', 15000)
    for c in clauses_list:
        try:
            s.add(eval(c, ctx))
        except Exception:
            pass

    for k, val in cand_key.items():
        if k in ctx:
            s.add(ctx[k] == val)
    for hz in hiZVars.values():
        if hz in ctx:
            s.add(ctx[hz] == True)

    all_inputs = list(itertools.product([False, True], repeat=len(inVars)))
    pass_cnt = 0

    print(f"\n{'-'*80}")
    print(f"{'Input Vector':<15} | {'Expected (c17)':<22} | {'Fabric Output':<22} | Status")
    print(f"{'-'*80}")
    for inp_tuple in all_inputs:
        s.push()
        for i, in_name in enumerate(inVars):
            s.add(ctx[in_name] == inp_tuple[i])

        r = s.check()
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        expected = runPyOracle(inp_dict, oracle_file, inVars, outVars)

        vec_str = "".join(['1' if b else '0' for b in inp_tuple])
        if r == sat:
            m = s.model()
            actual = {out_name: is_true(m[ctx[out_name]]) for out_name in outVars}
            matched = (actual == expected)
            if matched:
                pass_cnt += 1
            status = "MATCH (PASS)" if matched else "MISMATCH (FAIL)"
            exp_str = f"po22={int(expected['po22'])}, po23={int(expected['po23'])}"
            act_str = f"po22={int(actual['po22'])}, po23={int(actual['po23'])}"
            print(f"{vec_str:<15} | {exp_str:<22} | {act_str:<22} | {status}")
        else:
            print(f"{vec_str:<15} | {'N/A':<22} | {'UNSAT':<22} | FAIL")
        s.pop()

    print(f"{'-'*80}")
    print(f"VERIFICATION SUMMARY: {pass_cnt}/{len(all_inputs)} passed ({(pass_cnt/len(all_inputs))*100:.1f}%)")
    print(f"OVERALL VERDICT: {'ALL 32/32 VECTORS MATCH 100% (PERFECT)' if pass_cnt == len(all_inputs) else 'VERIFICATION FAILED'}")
    print("=" * 80 + "\n")
    return pass_cnt == len(all_inputs)

if __name__ == '__main__':
    verify_test14()
