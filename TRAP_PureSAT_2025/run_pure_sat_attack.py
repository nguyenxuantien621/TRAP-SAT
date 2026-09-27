#!/usr/bin/env python3
'''
Fast In-Memory SAT Attack & Truth Table Verification for TRAP Logic Locking
Pure Boolean SAT solving directly via Z3 CDCL engine.
'''

import os
import sys
import time
import re
import csv
import itertools
from z3 import *

def build_magnitude_comparator(B_bits: list, A_bits: list):
    n = len(B_bits)
    terms = []
    for i in range(n):
        eq_prefixes = [B_bits[j] == A_bits[j] for j in range(i)]
        cur_step = And(B_bits[i], Not(A_bits[i]))
        if eq_prefixes:
            terms.append(And(*eq_prefixes, cur_step))
        else:
            terms.append(cur_step)
    return Or(*terms)

def is_greater_3bit(*args): return build_magnitude_comparator(list(args[:3]), list(args[3:]))
def is_greater_4bit(*args): return build_magnitude_comparator(list(args[:4]), list(args[4:]))
def is_greater_5bit(*args): return build_magnitude_comparator(list(args[:5]), list(args[5:]))
def is_greater_6bit(*args): return build_magnitude_comparator(list(args[:6]), list(args[6:]))
def is_greater_7bit(*args): return build_magnitude_comparator(list(args[:7]), list(args[7:]))
def is_greater_8bit(*args): return build_magnitude_comparator(list(args[:8]), list(args[8:]))

def readZ3pl(trgtZ3: str):
    varsDict = {}
    funList = []
    with open(trgtZ3, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for line in lines:
        mtchObj = re.match(r'^\s*(?P<varID>\w+)\s*=\s*(?P<varType>(Bool)|(Int)|(BitVec))\([\',\"](?P<varName>\w+)[\',\"](?P<varArgs>\s*,.*)?\).*$', line)
        if mtchObj:
            varsDict[mtchObj.group('varID')] = (mtchObj.group('varType'), mtchObj.group('varArgs'))
    for line in lines:
        mtchObj = re.match(r'^\s*(?P<funID>\w+)\s*=\s*(?P<fun>[^\'\"]*)\n$', line)
        if mtchObj and mtchObj.group('fun') != 'Solver()':
            funList.append(mtchObj.group('fun'))
    return varsDict, funList

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

def runPyOracle(oracleIns: dict, oracleFile: str, inList: list, outList: list) -> dict:
    varsDict, funList = readZ3pl(oracleFile)
    s = Solver()
    z3Vars = {}
    for vName in varsDict.keys():
        z3Vars[vName] = Bool(vName)
    locs = {**z3Vars, 'Solver': Solver, 'Bool': Bool, 'And': And, 'Or': Or, 'Not': Not, 'Xor': Xor}
    for clauseStr in funList:
        try:
            clauseObj = eval(clauseStr, globals(), locs)
            s.add(clauseObj)
        except Exception:
            pass
    for inName, inVal in oracleIns.items():
        if inName in z3Vars:
            s.add(z3Vars[inName] == inVal)
    cktOut = {}
    if s.check() == sat:
        m = s.model()
        for outName in outList:
            if outName in z3Vars:
                cktOut[outName] = is_true(m[z3Vars[outName]])
    return cktOut

def get_ast_clauses_fast(funList: list, mapping: dict):
    '''
    Fast compiled AST generation for a list of clause strings under variable mapping.
    '''
    lines = []
    for old_v, new_v in mapping.items():
        lines.append(f"{old_v} = Bool('{new_v}')")
    for i, f in enumerate(funList):
        lines.append(f"__c_{i} = {f}")
    lines.append(f"__all_clauses = [{', '.join(f'__c_{i}' for i in range(len(funList)))}]")
    code = '\n'.join(lines)
    locs = {
        'Bool': Bool, 'And': And, 'Or': Or, 'Not': Not, 'Xor': Xor, 'Implies': Implies,
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit
    }
    exec(code, locs)
    return locs['__all_clauses']

def run_inmem_sat_attack(plLogicFile: str, ioCSVFile: str, oracleNetlist: str, benchName='bench'):
    t_start = time.time()
    print("=" * 80, flush=True)
    print(f"STARTING FAST IN-MEMORY SAT ATTACK: {benchName}", flush=True)
    print(f"Target logic file: {plLogicFile}", flush=True)
    
    inVars, keyVars, outVars, hiZVars = parsePL(ioCSVFile)
    print(f"Inputs ({len(inVars)}): {inVars}", flush=True)
    print(f"Outputs ({len(outVars)}): {outVars} | Tri-state validity: {hiZVars}", flush=True)
    print(f"Key variables: {len(keyVars)}", flush=True)
    
    varsDict, funList = readZ3pl(plLogicFile)
    
    # Identify static vs dynamic variables
    static_names = set(keyVars) | {x for x in varsDict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    dyn_names = set(varsDict.keys()) - static_names - set(inVars) - set(outVars)
    
    print(f"Total PL variables: {len(varsDict)} (Static: {len(static_names)}, Dynamic: {len(dyn_names)})", flush=True)
    print("=" * 80, flush=True)
    
    s_miter = Solver()
    
    # Base Miter copy 1
    map_m1 = {v: v for v in inVars}
    for v in static_names: map_m1[v] = f"{v}_1"
    for v in dyn_names: map_m1[v] = f"{v}_m1"
    for v in outVars: map_m1[v] = f"{v}_m1"
    for outV, hizV in hiZVars.items():
        if hizV in varsDict: map_m1[hizV] = f"{hizV}_m1"
            
    # Base Miter copy 2
    map_m2 = {v: v for v in inVars}
    for v in static_names: map_m2[v] = f"{v}_2"
    for v in dyn_names: map_m2[v] = f"{v}_m2"
    for v in outVars: map_m2[v] = f"{v}_m2"
    for outV, hizV in hiZVars.items():
        if hizV in varsDict: map_m2[hizV] = f"{hizV}_m2"
            
    print("Compiling initial Miter AST constraints...", flush=True)
    t_c0 = time.time()
    clauses_m1 = get_ast_clauses_fast(funList, map_m1)
    clauses_m2 = get_ast_clauses_fast(funList, map_m2)
    s_miter.add(clauses_m1)
    s_miter.add(clauses_m2)
    print(f"Miter constraints initialized in {time.time()-t_c0:.3f}s.", flush=True)
    
    # Miter output difference condition
    out_diff_terms = []
    if not hiZVars:
        for v in outVars:
            out_diff_terms.append(Xor(Bool(f"{v}_m1"), Bool(f"{v}_m2")))
    else:
        for outV, hizV in hiZVars.items():
            out_diff_terms.append(And(Xor(Bool(f"{outV}_m1"), Bool(f"{outV}_m2")), Or(Bool(f"{hizV}_m1"), Bool(f"{hizV}_m2"))))
    s_miter.add(Or(out_diff_terms))
    
    s_key = Solver()
    allDIPs = []
    iters = 1
    maxRounds = (2 ** len(inVars)) + 1
    func_funList = [c for c in funList if 'is_greater_' not in c and 'cnt' not in c]
    
    print("\nStarting iterative DIP search...", flush=True)
    while iters < maxRounds:
        t_r_start = time.time()
        res = s_miter.check()
        t_r_solve = time.time() - t_r_start
        
        if res != sat:
            print(f"Miter check returned {res} at round #{iters} in {t_r_solve:.3f}s. All DIPs found!", flush=True)
            break
            
        m = s_miter.model()
        dip = {}
        for inv in inVars:
            dip[inv] = is_true(m[Bool(inv)])
            
        print(f"Round #{iters} (solved in {t_r_solve:.3f}s): Extracted DIP = {dip}", flush=True)
        allDIPs.append(dip)
        
        oracleOut = runPyOracle(dip, oracleNetlist, inVars, outVars)
        print(f"  Oracle response = {oracleOut}", flush=True)
        
        suff = f"_cp{iters}"
        
        # Miter Copy 1:
        map_miter_cp1 = {}
        for v in static_names: map_miter_cp1[v] = f"{v}_1"
        for v in dyn_names: map_miter_cp1[v] = f"{v}{suff}_1"
        for v in inVars: map_miter_cp1[v] = f"{v}{suff}_1"
        for v in outVars: map_miter_cp1[v] = f"{v}{suff}_1"
        for outV, hizV in hiZVars.items():
            if hizV in varsDict: map_miter_cp1[hizV] = f"{hizV}{suff}_1"
            
        # Miter Copy 2:
        map_miter_cp2 = {}
        for v in static_names: map_miter_cp2[v] = f"{v}_2"
        for v in dyn_names: map_miter_cp2[v] = f"{v}{suff}_2"
        for v in inVars: map_miter_cp2[v] = f"{v}{suff}_2"
        for v in outVars: map_miter_cp2[v] = f"{v}{suff}_2"
        for outV, hizV in hiZVars.items():
            if hizV in varsDict: map_miter_cp2[hizV] = f"{hizV}{suff}_2"
            
        s_miter.add(get_ast_clauses_fast(func_funList, map_miter_cp1))
        s_miter.add(get_ast_clauses_fast(func_funList, map_miter_cp2))
        
        for inv, val in dip.items():
            s_miter.add(Bool(f"{inv}{suff}_1") == val)
            s_miter.add(Bool(f"{inv}{suff}_2") == val)
        for outv, val in oracleOut.items():
            s_miter.add(Bool(f"{outv}{suff}_1") == val)
            s_miter.add(Bool(f"{outv}{suff}_2") == val)
        for outv, hizv in hiZVars.items():
            s_miter.add(Bool(f"{hizv}{suff}_1") == True)
            s_miter.add(Bool(f"{hizv}{suff}_2") == True)
            
        block_terms = [Bool(inv) != val for inv, val in dip.items()]
        s_miter.add(Or(block_terms))
        
        # Key Solver:
        map_key_cp = {}
        for v in static_names: map_key_cp[v] = v
        for v in dyn_names: map_key_cp[v] = f"{v}{suff}"
        for v in inVars: map_key_cp[v] = f"{v}{suff}"
        for v in outVars: map_key_cp[v] = f"{v}{suff}"
        for outv, hizv in hiZVars.items():
            if hizv in varsDict: map_key_cp[hizv] = f"{hizv}{suff}"
            
        if iters == 1:
            s_key.add(get_ast_clauses_fast(funList, map_key_cp))
        else:
            s_key.add(get_ast_clauses_fast(func_funList, map_key_cp))
            
        for inv, val in dip.items():
            s_key.add(Bool(f"{inv}{suff}") == val)
        for outv, val in oracleOut.items():
            s_key.add(Bool(f"{outv}{suff}") == val)
        for outv, hizv in hiZVars.items():
            s_key.add(Bool(f"{hizv}{suff}") == True)
            
        iters += 1
        
    print("\nSolving for extracted key...", flush=True)
    t_k_start = time.time()
    key_res = s_key.check()
    t_k_solve = time.time() - t_k_start
    
    if key_res != sat:
        print(f"ERROR: Final Key solve returned {key_res} in {t_k_solve:.3f}s!", flush=True)
        return False, None, allDIPs
        
    key_model = s_key.model()
    extracted_keys = {}
    for kv in keyVars:
        extracted_keys[kv] = is_true(key_model[Bool(kv)])
        
    print(f"SUCCESS: Key extracted in {t_k_solve:.3f}s! Total keys: {len(extracted_keys)}", flush=True)
    active_keys = [k for k, v in extracted_keys.items() if v]
    print(f"Active (True) Keys ({len(active_keys)}): {active_keys}", flush=True)
    
    work_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'work')
    os.makedirs(work_dir, exist_ok=True)
    out_key_csv = os.path.join(work_dir, f'extracted_key_{benchName}.csv')
    with open(out_key_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        for k, v in extracted_keys.items():
            writer.writerow([k, v])
    print(f"Saved extracted key to: {out_key_csv}", flush=True)
    
    total_time = time.time() - t_start
    print(f"Total Attack Time: {total_time:.3f}s | DIP Rounds: {len(allDIPs)}", flush=True)
    
    print("\n" + "=" * 80, flush=True)
    print(f"STARTING EXHAUSTIVE 100% TRUTH TABLE VERIFICATION ({2**len(inVars)} vectors)", flush=True)
    print("=" * 80, flush=True)
    
    # Pre-build base verification assertions
    s_verify = Solver()
    map_ver = {v: v for v in varsDict.keys()}
    s_verify.add(get_ast_clauses_fast(funList, map_ver))
    for k, v in extracted_keys.items():
        s_verify.add(Bool(k) == v)
    base_assertions = s_verify.assertions()
        
    num_inputs = len(inVars)
    total_patterns = 1 << num_inputs
    matches = 0
    mismatches = 0
    invalid_outputs = 0
    
    results = []
    
    for idx in range(total_patterns):
        in_vec = {}
        for bit_idx, inv in enumerate(inVars):
            in_vec[inv] = bool((idx >> (num_inputs - 1 - bit_idx)) & 1)
            
        oracle_res = runPyOracle(in_vec, oracleNetlist, inVars, outVars)
        
        s_test = Solver()
        s_test.add(base_assertions)
        for inv, val in in_vec.items():
            s_test.add(Bool(inv) == val)
            
        if s_test.check() != sat:
            status = "FAIL (UNSAT - Broken Route)"
            mismatches += 1
            results.append((idx, in_vec, oracle_res, None, None, status))
            continue
            
        m_ver = s_test.model()
        fab_out = {}
        for ov in outVars:
            fab_out[ov] = is_true(m_ver[Bool(ov)])
            
        fab_valid = {}
        all_valid = True
        for ov, hizv in hiZVars.items():
            val = is_true(m_ver[Bool(hizv)])
            fab_valid[ov] = val
            if not val:
                all_valid = False
                
        is_match = (fab_out == oracle_res) and all_valid
        if is_match:
            status = "MATCH (PASS)"
            matches += 1
        elif not all_valid:
            status = "FAIL (Invalid Tri-State)"
            invalid_outputs += 1
            mismatches += 1
        else:
            status = "FAIL (Mismatch)"
            mismatches += 1
            
        results.append((idx, in_vec, oracle_res, fab_out, fab_valid, status))
        
    print(f"\n| # | {' | '.join(inVars)} | Golden Oracle | Deobfuscated Fabric | Valid Flags | Status |", flush=True)
    print(f"|---|{'---|' * len(inVars)}---|---|---|---|", flush=True)
    for idx, in_vec, ora_out, fab_out, fab_valid, status in results:
        in_str = " | ".join(["1" if in_vec[inv] else "0" for inv in inVars])
        ora_str = ", ".join([f"{k}={'1' if v else '0'}" for k, v in ora_out.items()])
        fab_str = ", ".join([f"{k}={'1' if v else '0'}" for k, v in fab_out.items()]) if fab_out else "N/A"
        val_str = ", ".join([f"{k}={'1' if v else '0'}" for k, v in fab_valid.items()]) if fab_valid else "N/A"
        print(f"| {idx:02d} | {in_str} | {ora_str} | {fab_str} | {val_str} | {status} |", flush=True)
        
    print("\n" + "=" * 80, flush=True)
    print(f"VERIFICATION SUMMARY: {benchName}", flush=True)
    print(f"Total Patterns: {total_patterns} | Matches: {matches}/{total_patterns} ({(matches/total_patterns)*100:.1f}%) | Mismatches: {mismatches}", flush=True)
    print("=" * 80, flush=True)
    
    return (matches == total_patterns), extracted_keys, results

if __name__ == '__main__':
    base_path = r"C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025"
    
    # Test 14: 2x2 C17
    run_inmem_sat_attack(
        os.path.join(base_path, "test/Test14-TRAP_2x2_C17/trap2x2C17.py"),
        os.path.join(base_path, "test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv"),
        os.path.join(base_path, "test/Test14-TRAP_2x2_C17/c17.py"),
        "Test14_TRAP_2x2_C17"
    )
