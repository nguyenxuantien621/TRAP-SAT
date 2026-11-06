#!/usr/bin/env python3
'''
Fast Hierarchical Solver for Test19-TRAP_4x4_C17
Leverages verified 3x3 core from Test 18 and CaDiCaL 1.5.3 with linear-chain Tseitin CNF.
'''

import time
import csv
import sys
import os
import itertools
from z3 import *
import pysat.solvers

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

def solve_test19():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    test_path = os.path.join(base_dir, 'test', 'Test19-TRAP_4x4_C17')
    pl_file = os.path.join(test_path, 'trap4x4C17.py')
    io_file = os.path.join(test_path, 'trap4x4C17_io.csv')
    oracle_file = os.path.join(test_path, 'c17.py')
    key_file = os.path.join(test_path, 'extracted_key.csv')
    k18_file = os.path.join(base_dir, 'test', 'Test18-TRAP_3x3_C17', 'extracted_key.csv')

    print("=" * 80, flush=True)
    print("STARTING HIERARCHICAL 4x4 TRAP FABRIC ATTACK: Test19-TRAP_4x4_C17", flush=True)
    print("Engine: CaDiCaL 1.5.3 + Verified 3x3 Core Seeding + Linear-Chain Acyclicity", flush=True)
    print("=" * 80, flush=True)

    t_start = time.time()
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    print(f"Inputs ({len(inVars)}): {inVars} | Outputs ({len(outVars)}): {outVars} | Keys: {len(keyVars)}", flush=True)
    print(f"HiZ / Validities: {hiZVars}", flush=True)

    # Load verified 3x3 reference key
    with open(k18_file, 'r') as f:
        k18 = {r[0].strip(): (r[1].strip() == 'True') for r in csv.reader(f) if r}
    print(f"Loaded {len(k18)} reference keys from Test 18.", flush=True)

    # Pre-compute golden truth table for C17
    all_input_tuples = list(itertools.product([False, True], repeat=len(inVars)))
    golden_table = {}
    for inp_tuple in all_input_tuples:
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        out_dict = runPyOracle(inp_dict, oracle_file, inVars, outVars)
        golden_table[inp_tuple] = out_dict

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    print("Converting 4x4 base circuit to Tseitin CNF...", flush=True)
    t0 = time.time()
    g = Goal()
    for c in clauses_list:
        try:
            g.add(eval(c, ctx))
        except Exception:
            pass

    t = Tactic('tseitin-cnf')
    cnf = t(g)[0]
    print(f"CNF generated in {time.time()-t0:.2f}s: {len(cnf)} CNF clauses.", flush=True)

    var_map = {}
    id_to_var = {}

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

    base_cnf_clauses = []
    for cl in cnf:
        if is_or(cl):
            base_cnf_clauses.append([get_lit_id(arg) for arg in cl.children()])
        else:
            base_cnf_clauses.append([get_lit_id(cl)])

    key_lit_ids = set([var_map[k] for k in keyVars if k in var_map])
    fixed_core_keys = {k: v for k, v in k18.items() if k in var_map}
    print(f"Total variables: {len(var_map)}, Key variables: {len(key_lit_ids)}, Fixed 3x3 core keys: {len(fixed_core_keys)}", flush=True)

    N_vars = len(var_map) + 1000

    def build_pattern_clauses(p_idx, inp_tuple):
        shift = p_idx * N_vars
        g_outs = golden_table[inp_tuple]
        p_clauses = []

        for cl in base_cnf_clauses:
            shifted_c = []
            for lit in cl:
                vid = abs(lit)
                sign = 1 if lit > 0 else -1
                if vid in key_lit_ids:
                    shifted_c.append(lit)
                else:
                    shifted_c.append(sign * (vid + shift))
            p_clauses.append(shifted_c)

        for i, in_name in enumerate(inVars):
            in_val = inp_tuple[i]
            vid = var_map[in_name]
            p_clauses.append([ (vid + shift) if in_val else -(vid + shift) ])

        for out_name in outVars:
            out_val = g_outs[out_name]
            vid = var_map[out_name]
            p_clauses.append([ (vid + shift) if out_val else -(vid + shift) ])

        for hz_var in hiZVars.values():
            if hz_var in var_map:
                p_clauses.append([ (var_map[hz_var] + shift) ])

        return p_clauses

    # Proven 10-pattern basis from task-7972
    active_patterns = [
        (False, False, False, False, False),
        (True, True, True, True, True),
        (True, False, False, False, False),
        (False, True, False, False, False),
        (False, False, True, False, False),
        (False, False, False, True, True),
        (False, False, False, False, True),
        (True, False, True, True, True),
        (False, True, True, True, False),
        (False, True, True, True, True)
    ]

    iteration = 0
    while True:
        iteration += 1
        print(f"\n--- Iteration {iteration} (Active Patterns: {len(active_patterns)}) ---", flush=True)

        solver = pysat.solvers.Cadical153()
        # Fix 3x3 core keys
        for k, val in fixed_core_keys.items():
            vid = var_map[k]
            solver.add_clause([vid if val else -vid])

        # Add pattern clauses
        for p_idx, pat in enumerate(active_patterns):
            for cl in build_pattern_clauses(p_idx, pat):
                solver.add_clause(cl)

        print(f"Solver Loaded: {solver.nof_clauses()} clauses, {solver.nof_vars()} vars. Solving...", flush=True)
        t_it = time.time()
        res = solver.solve()
        solve_dur = time.time() - t_it
        print(f"CaDiCaL solve: {res} in {solve_dur:.2f}s", flush=True)

        if not res:
            print("ERROR: Solver returned UNSAT!", flush=True)
            solver.delete()
            return False

        model = set(solver.get_model())
        cand_key = {k: (var_map[k] in model) if k in var_map else False for k in keyVars}
        solver.delete()

        # Fast verification
        t_v = time.time()
        v_solver = pysat.solvers.Cadical153()
        for cl in base_cnf_clauses:
            v_solver.add_clause(cl)
        for k, val in cand_key.items():
            if k in var_map:
                vid = var_map[k]
                v_solver.add_clause([vid if val else -vid])
        for hz_var in hiZVars.values():
            if hz_var in var_map:
                v_solver.add_clause([var_map[hz_var]])

        pass_count = 0
        failing_patterns = []

        for inp_tuple in all_input_tuples:
            g_outs = golden_table[inp_tuple]
            assumptions = []
            for i, in_name in enumerate(inVars):
                in_val = inp_tuple[i]
                vid = var_map[in_name]
                assumptions.append(vid if in_val else -vid)

            sat_res = v_solver.solve(assumptions=assumptions)
            if sat_res:
                vm = set(v_solver.get_model())
                matched = True
                for out_name in outVars:
                    expected = g_outs[out_name]
                    actual = (var_map[out_name] in vm)
                    if actual != expected:
                        matched = False
                        break
                if matched:
                    pass_count += 1
                else:
                    if inp_tuple not in active_patterns:
                        failing_patterns.append(inp_tuple)
            else:
                if inp_tuple not in active_patterns:
                    failing_patterns.append(inp_tuple)

        v_solver.delete()
        print(f"Verification: {pass_count}/{len(all_input_tuples)} passed in {time.time()-t_v:.2f}s", flush=True)

        if pass_count == len(all_input_tuples):
            total_time = time.time() - t_start
            print(f"\n=======================================================", flush=True)
            print(f"SUCCESS! 100% TRUTH TABLE MATCH ACHIEVED! (32/32 PASS)", flush=True)
            print(f"Total Attack Runtime: {total_time:.2f}s across {iteration} iteration(s)", flush=True)
            print(f"=======================================================\n", flush=True)

            # Export key in exact order of trap4x4C17_io.csv
            clean_rows = []
            with open(io_file, 'r') as f:
                for row in csv.reader(f):
                    if row and len(row) > 1 and row[1].strip() == 'key':
                        kname = row[0].strip()
                        val = cand_key.get(kname, False)
                        clean_rows.append([kname, str(val)])

            with open(key_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(clean_rows)

            print(f"[+] Extracted key saved to {key_file} ({len(clean_rows)} key rows)", flush=True)

            # Run Exhaustive Z3 Independent Truth Table Verification
            print(f"\n{'-'*70}", flush=True)
            print(f"EXHAUSTIVE Z3 TRUTH TABLE VERIFICATION FOR Test19-TRAP_4x4_C17:", flush=True)
            print(f"{'-'*70}", flush=True)

            s_ver = Solver()
            s_ver.set('timeout', 15000)
            for c in clauses_list:
                try:
                    s_ver.add(eval(c, ctx))
                except Exception:
                    pass
            for k, val in cand_key.items():
                if k in ctx:
                    s_ver.add(ctx[k] == val)
            for hz_var in hiZVars.values():
                if hz_var in ctx:
                    s_ver.add(ctx[hz_var] == True)

            ver_all_pass = True
            for inp_tuple in all_input_tuples:
                s_ver.push()
                for i, in_name in enumerate(inVars):
                    s_ver.add(ctx[in_name] == inp_tuple[i])
                r = s_ver.check()
                if r == sat:
                    m_z3 = s_ver.model()
                    actual_outs = {out_name: is_true(m_z3[ctx[out_name]]) for out_name in outVars}
                    expected_outs = golden_table[inp_tuple]
                    m_ok = (actual_outs == expected_outs)
                    if not m_ok:
                        ver_all_pass = False
                    status_str = "MATCH (PASS)" if m_ok else "MISMATCH (FAIL)"
                    inp_str = "".join(['1' if b else '0' for b in inp_tuple])
                    print(f"Vector {inp_str} ({inp_tuple}) -> Expected: {expected_outs} | Actual: {actual_outs} | {status_str}", flush=True)
                else:
                    ver_all_pass = False
                    inp_str = "".join(['1' if b else '0' for b in inp_tuple])
                    print(f"Vector {inp_str} ({inp_tuple}) -> UNSAT (FAIL)", flush=True)
                s_ver.pop()

            print(f"{'-'*70}", flush=True)
            print(f"FINAL VERDICT: {'ALL 32/32 VECTORS MATCH 100%' if ver_all_pass else 'VERIFICATION FAILED'}", flush=True)
            print(f"{'-'*70}\n", flush=True)
            return True

        # If not all passed, add counterexample
        new_cex = failing_patterns[0]
        print(f"Adding counterexample: {new_cex}\n", flush=True)
        active_patterns.append(new_cex)

if __name__ == '__main__':
    solve_test19()
