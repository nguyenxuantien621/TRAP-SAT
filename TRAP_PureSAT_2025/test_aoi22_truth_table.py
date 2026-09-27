#!/usr/bin/env python3
'''
Independent Truth Table Equivalence Checker for Test15 (AOI22 on 2x1 TRAP Fabric)
Compares Oracle ASIC vs TRAP Fabric with extracted key across 100% truth table (16 input patterns).
'''

import csv
from z3 import *
from src.pysatAttack import (
    readZ3pl, queryOracle,
    is_greater_3bit, is_greater_4bit, is_greater_5bit,
    is_greater_6bit, is_greater_7bit, is_greater_8bit,
    build_magnitude_comparator
)

def main():
    keyCSV = 'test/Test15-TRAP_2x1_AOI22/extracted_key.csv'
    oracleFile = 'test/Test15-TRAP_2x1_AOI22/aoi22PL.py'
    fabricPL = 'test/Test15-TRAP_2x1_AOI22/trap2x1AOI22.py'
    inVars = ['a', 'b', 'c', 'd']
    outVars = ['o']

    print("\nLoading files...")
    # 1. Load extracted key
    extracted_key = {}
    with open(keyCSV, 'r', encoding='utf-8') as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                extracted_key[row[0].strip()] = (row[1].strip().lower() == 'true')
    print(f"[*] Loaded {len(extracted_key)} key bits from {keyCSV}")

    # 2. Load Fabric Model
    varsDict, funList = readZ3pl(fabricPL)
    exec_ctx = {k: Bool(k) for k in varsDict.keys()}
    exec_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['is_greater_4bit'] = is_greater_4bit
    exec_ctx['is_greater_5bit'] = is_greater_5bit
    exec_ctx['is_greater_6bit'] = is_greater_6bit
    exec_ctx['is_greater_7bit'] = is_greater_7bit
    exec_ctx['is_greater_8bit'] = is_greater_8bit
    exec_ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})

    s = Solver()
    for c in funList:
        try:
            s.add(eval(c, exec_ctx))
        except Exception:
            pass

    # 3. Pin extracted key
    for k, v in extracted_key.items():
        if k in exec_ctx:
            s.add(exec_ctx[k] == v)

    print("\n" + "=" * 65)
    print(f"{'Input (a,b,c,d)':<18} | {'Oracle Output':<14} | {'Fabric Output':<14} | {'Result':<10}")
    print("=" * 65)

    all_matched = True
    for a_val in [False, True]:
        for b_val in [False, True]:
            for c_val in [False, True]:
                for d_val in [False, True]:
                    inp = {'a': a_val, 'b': b_val, 'c': c_val, 'd': d_val}
                    
                    # Query Oracle directly
                    ora_out = queryOracle(inp, oracleFile, inVars, outVars)['o']
                    
                    # Query Fabric with key
                    s.push()
                    s.add(
                        exec_ctx['a'] == a_val,
                        exec_ctx['b'] == b_val,
                        exec_ctx['c'] == c_val,
                        exec_ctx['d'] == d_val
                    )
                    res = s.check()
                    if res == sat:
                        fab_out = bool(s.model()[exec_ctx['o']])
                    else:
                        fab_out = "UNSAT"
                    s.pop()
                    
                    is_match = (fab_out == ora_out)
                    if not is_match:
                        all_matched = False
                    
                    match_str = "MATCH [OK]" if is_match else "MISMATCH [X]"
                    inp_str = f"({int(a_val)}, {int(b_val)}, {int(c_val)}, {int(d_val)})"
                    print(f"{inp_str:<18} | {str(ora_out):<14} | {str(fab_out):<14} | {match_str}")

    print("=" * 65)
    if all_matched:
        print("VERIFICATION CONCLUSION: 100% MATCH ACROSS ALL 16 PATTERNS!")
    else:
        print("VERIFICATION CONCLUSION: MISMATCH DETECTED!")
    print("=" * 65 + "\n")

if __name__ == '__main__':
    main()
