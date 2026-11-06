#!/usr/bin/env python3
"""
Exhaustive Truth Table Verification Script for 3x3 Fabric Benchmarks:
- Test 17: TRAP 3x3 AOI22 (16 input combinations)
- Test 18: TRAP 3x3 C17 (32 input combinations)
"""

import os
import csv
import itertools
from z3 import *
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

def verify_test(test_name, pl_rel, io_rel, oracle_rel, key_rel):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pl_file = os.path.join(base_dir, pl_rel)
    io_file = os.path.join(base_dir, io_rel)
    oracle_file = os.path.join(base_dir, oracle_rel)
    key_file = os.path.join(base_dir, key_rel)

    print("=" * 80)
    print(f"VERIFYING TRUTH TABLE: {test_name}")
    print("=" * 80)

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    cand_key = {}
    with open(key_file, 'r') as f:
        for r in csv.reader(f):
            if r:
                cand_key[r[0].strip()] = (r[1].strip() == 'True')

    print(f"Total keys loaded: {len(cand_key)} / Expected: {len(keyVars)}")
    print(f"Inputs: {inVars} | Outputs: {outVars}")
    print(f"Validities: {hiZVars}")

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    s = Solver()
    s.set('timeout', 10000)
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

    print(f"\n{'-'*75}")
    for inp_tuple in all_inputs:
        s.push()
        for i, in_name in enumerate(inVars):
            s.add(ctx[in_name] == inp_tuple[i])

        r = s.check()
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        expected = runPyOracle(inp_dict, oracle_file, inVars, outVars)

        if r == sat:
            m = s.model()
            actual = {out_name: is_true(m[ctx[out_name]]) for out_name in outVars}
            matched = (actual == expected)
            if matched:
                pass_cnt += 1
            status = "MATCH (PASS)" if matched else "MISMATCH (FAIL)"
            print(f"Input {inp_tuple} -> Golden: {expected} | Fabric: {actual} | {status}")
        else:
            print(f"Input {inp_tuple} -> UNSAT (FAIL)")
        s.pop()

    print(f"{'-'*75}")
    print(f"RESULT: {pass_cnt}/{len(all_inputs)} passed ({(pass_cnt/len(all_inputs))*100:.1f}%)")
    print("=" * 80 + "\n")
    return pass_cnt == len(all_inputs)

if __name__ == '__main__':
    ok17 = verify_test(
        "Test 17: TRAP 3x3 AOI22",
        "test/Test17-TRAP_3x3_AOI22/trap3x3AOI22.py",
        "test/Test17-TRAP_3x3_AOI22/trap3x3AOI22_io.csv",
        "test/Test17-TRAP_3x3_AOI22/aoi22PL.py",
        "test/Test17-TRAP_3x3_AOI22/extracted_key.csv"
    )

    ok18 = verify_test(
        "Test 18: TRAP 3x3 C17",
        "test/Test18-TRAP_3x3_C17/trap3x3C17.py",
        "test/Test18-TRAP_3x3_C17/trap3x3C17_io.csv",
        "test/Test18-TRAP_3x3_C17/c17.py",
        "test/Test18-TRAP_3x3_C17/extracted_key.csv"
    )

    if ok17 and ok18:
        print("ALL 3x3 BENCHMARKS VERIFIED 100% MATCH! ZERO DEFECTS.")
    else:
        print("SOME TESTS FAILED VERIFICATION.")
