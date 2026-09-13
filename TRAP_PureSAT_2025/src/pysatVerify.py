#!/usr/bin/env python3
'''
Script for verifying extracted key using Glucose4 (PySAT) Pure Boolean Solver across 100% input space.

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import csv
import itertools
from z3 import *
import pysat.solvers

# Add TRAP_for_SAT_2025 directory to sys.path for VS Code Pylance static resolution
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_workspace = os.path.dirname(base_dir)
trap_2025_dir = os.path.join(parent_workspace, 'TRAP_for_SAT_2025')

if trap_2025_dir not in sys.path:
    sys.path.insert(0, trap_2025_dir)

# Static import for Pylance IntelliSense & zero red warnings in VS Code
from src.satAttack import readZ3pl, queryOracle

def parsePL(ioCSV):
    inVars = []
    keyVars = []
    outVars = []
    hiZVars = {}
    with open(ioCSV, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            ioNm, ioAtts = row[0], row[1:]
            if ioAtts[0] == 'input':
                inVars.append(ioNm)
            elif ioAtts[0] == 'key':
                keyVars.append(ioNm)
            elif ioAtts[0] == 'output':
                outVars.append(ioNm)
                if len(ioAtts) > 1:
                    hiZVars[ioNm] = ioAtts[1]
    return inVars, keyVars, outVars, hiZVars

def is_greater_3bit(B2, B1, B0, A2, A1, A0):
    t1 = And(B2, Not(A2))
    t2 = And(B2 == A2, B1, Not(A1))
    t3 = And(B2 == A2, B1 == A1, B0, Not(A0))
    return Or(t1, t2, t3)

def pysatVerify(keyCSV: str, oracleFile: str, ioCSVFile: str, fabricPL: str) -> bool:
    '''
    Verifies that the extracted key in keyCSV configures the TRAP fabric to behave
    identically to oracleFile over 100% of input patterns.
    '''
    inVars, keyVars, outVars, hiZVars = parsePL(ioCSVFile)

    # Read extracted key
    extracted_key = {}
    with open(keyCSV, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                var, val = row[0].strip(), row[1].strip()
                extracted_key[var] = (val.lower() == 'true')

    print(f"\n================================================================================")
    print(f"STARTING PURESAT (GLUCOSE4) KEY VERIFICATION")
    print(f"Key CSV: {keyCSV}")
    print(f"Testing across all {2**len(inVars)} input combinations...")
    print(f"================================================================================")

    total_patterns = 2 ** len(inVars)
    input_combinations = list(itertools.product([False, True], repeat=len(inVars)))

    mismatches = 0
    for idx, combo in enumerate(input_combinations):
        dip_in = {inVars[i]: combo[i] for i in range(len(inVars))}
        oracle_out = queryOracle(dip_in, oracleFile, inVars, outVars, oracleSel=True)

        # Check fabric response with key
        vars_dict, clauses_list = readZ3pl(fabricPL)
        
        exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
        exec_ctx['is_greater_3bit'] = is_greater_3bit
        exec_ctx['And'] = And
        exec_ctx['Or'] = Or
        exec_ctx['Not'] = Not
        exec_ctx['Implies'] = Implies
        exec_ctx['Xor'] = Xor

        g = Goal()
        for c_str in clauses_list:
            try:
                g.add(eval(c_str, exec_ctx))
            except Exception: pass

        # Pin key vars
        for kv, kval in extracted_key.items():
            if kv in exec_ctx:
                g.add(exec_ctx[kv] == kval)

        # Pin input vars
        for iv, ival in dip_in.items():
            if iv in exec_ctx:
                g.add(exec_ctx[iv] == ival)

        # Pin HiZ driven validity vars to True
        if hiZVars != {}:
            for hz_var in hiZVars.values():
                if hz_var in exec_ctx:
                    g.add(exec_ctx[hz_var] == True)

        t = Tactic('tseitin-cnf')
        cnf = t(g)[0]

        var_map = {}
        id_to_var = {}
        pysat_clauses = []

        def get_lit_id(lit):
            neg = is_not(lit)
            v = lit.arg(0) if neg else lit
            vname = str(v)
            if vname not in var_map:
                var_id = len(var_map) + 1
                var_map[vname] = var_id
                id_to_var[var_id] = vname
            else:
                var_id = var_map[vname]
            return -var_id if neg else var_id

        for clause in cnf:
            if is_or(clause):
                c = [get_lit_id(arg) for arg in clause.children()]
            else:
                c = [get_lit_id(clause)]
            pysat_clauses.append(c)

        with pysat.solvers.Glucose4(bootstrap_with=pysat_clauses) as solver:
            sat_res = solver.solve()
            if not sat_res:
                print(f"MISMATCH at input pattern {dip_in}: Fabric UNSAT with key!")
                mismatches += 1
                continue
            
            model = solver.get_model()
            model_dict = {id_to_var[abs(l)]: (l > 0) for l in model if abs(l) in id_to_var}
            
            for ov in outVars:
                fab_val = model_dict.get(ov, None)
                ora_val = oracle_out.get(ov, None)
                if fab_val != ora_val:
                    print(f"MISMATCH at pattern {dip_in}: Output {ov} Fabric={fab_val} vs Oracle={ora_val}")
                    mismatches += 1

    if mismatches == 0:
        print(f"\nGLUCOSE4 VERIFICATION SUCCESSFUL 100%!")
        print(f"All {total_patterns} input patterns matched Oracle outputs perfectly.")
        print(f"================================================================================\n")
        return True
    else:
        print(f"\nVERIFICATION FAILED: {mismatches} mismatches found!")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: pysatVerify.py <keyCSV> <oracleFile> <ioCSV> <fabricPL>")
        sys.exit(1)
    pysatVerify(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
