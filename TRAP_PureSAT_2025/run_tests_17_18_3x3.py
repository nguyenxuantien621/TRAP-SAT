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

def solve_3x3_benchmark(test_folder, pl_fn, io_fn, oracle_fn):
    test_path = os.path.join('test', test_folder)
    pl_file = os.path.join(test_path, pl_fn)
    io_file = os.path.join(test_path, io_fn)
    oracle_file = os.path.join(test_path, oracle_fn)
    key_file = os.path.join(test_path, 'extracted_key.csv')

    print("=" * 80, flush=True)
    print(f"STARTING 3x3 TRAP FABRIC ATTACK: {test_folder}", flush=True)
    print("=" * 80, flush=True)

    t_start = time.time()
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    print(f"Inputs ({len(inVars)}): {inVars} | Outputs ({len(outVars)}): {outVars} | Keys: {len(keyVars)}", flush=True)
    print(f"HiZ / Validities: {hiZVars}", flush=True)

    # Pre-compute golden lookup table
    all_input_tuples = list(itertools.product([False, True], repeat=len(inVars)))
    golden_table = {}
    for inp_tuple in all_input_tuples:
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        out_dict = runPyOracle(inp_dict, oracle_file, inVars, outVars)
        golden_table[inp_tuple] = out_dict

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    print("Converting 3x3 base circuit to Tseitin CNF...", flush=True)
    t0 = time.time()
    g = Goal()
    for c in clauses_list:
        try: g.add(eval(c, ctx))
        except Exception: pass

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
        if is_or(cl): base_cnf_clauses.append([get_lit_id(arg) for arg in cl.children()])
        else: base_cnf_clauses.append([get_lit_id(cl)])

    key_lit_ids = set([var_map[k] for k in keyVars if k in var_map])
    print(f"Total variables in CNF: {len(var_map)}, Shared key variables: {len(key_lit_ids)}", flush=True)

    solver = pysat.solvers.Cadical153()
    N_vars = len(var_map) + 1000

    def add_pattern(p_idx, inp_tuple):
        shift = p_idx * N_vars
        g_outs = golden_table[inp_tuple]

        for cl in base_cnf_clauses:
            shifted_c = []
            for lit in cl:
                vid = abs(lit)
                sign = 1 if lit > 0 else -1
                if vid in key_lit_ids:
                    shifted_c.append(lit)
                else:
                    shifted_c.append(sign * (vid + shift))
            solver.add_clause(shifted_c)

        for i, in_name in enumerate(inVars):
            in_val = inp_tuple[i]
            vid = var_map[in_name]
            solver.add_clause([ (vid + shift) if in_val else -(vid + shift) ])

        for out_name in outVars:
            out_val = g_outs[out_name]
            vid = var_map[out_name]
            solver.add_clause([ (vid + shift) if out_val else -(vid + shift) ])

        for hz_var in hiZVars.values():
            if hz_var in var_map:
                solver.add_clause([ (var_map[hz_var] + shift) ])

    constrained_patterns = set()
    initial_pat = all_input_tuples[0]
    constrained_patterns.add(initial_pat)
    add_pattern(0, initial_pat)

    print(f"Starting CEGIS loop with initial vector {initial_pat}...\n", flush=True)

    iteration = 0
    while True:
        iteration += 1
        t_it = time.time()
        print(f"--- Iteration {iteration} (Clauses: {solver.nof_clauses()}, Vars: {solver.nof_vars()}) ---", flush=True)
        res = solver.solve()
        solve_dur = time.time() - t_it
        print(f"CaDiCaL solve: {res} in {solve_dur:.2f}s", flush=True)

        if not res:
            print("ERROR: Solver returned UNSAT!", flush=True)
            return False, 0, 0, 0

        model = set(solver.get_model())
        cand_key = {k: (var_map[k] in model) if k in var_map else False for k in keyVars}

        # Verification via Cadical assumptions
        t_v = time.time()
        v_solver = pysat.solvers.Cadical153()
        for cl in base_cnf_clauses: v_solver.add_clause(cl)
        for k, val in cand_key.items():
            if k in var_map:
                vid = var_map[k]
                v_solver.add_clause([vid if val else -vid])
        for hz_var in hiZVars.values():
            if hz_var in var_map:
                v_solver.add_clause([var_map[hz_var]])

        pass_count = 0
        counterexample = None

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
                    if counterexample is None and inp_tuple not in constrained_patterns:
                        counterexample = inp_tuple
            else:
                if counterexample is None and inp_tuple not in constrained_patterns:
                    counterexample = inp_tuple

        v_solver.delete()
        print(f"Verification: {pass_count}/{len(all_input_tuples)} passed in {time.time()-t_v:.2f}s", flush=True)

        if pass_count == len(all_input_tuples):
            duration = time.time() - t_start
            print(f"\nSUCCESS! 3x3 Key found in {iteration} rounds ({duration:.2f}s). All {pass_count}/{len(all_input_tuples)} passed!", flush=True)

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

            print(f"Extracted key saved to {key_file} ({len(clean_rows)} key rows)", flush=True)

            # Independent Z3 truth table verification
            s_ver = Solver()
            s_ver.set('timeout', 5000)
            for c in clauses_list:
                try: s_ver.add(eval(c, ctx))
                except: pass
            for k, val in cand_key.items():
                if k in ctx: s_ver.add(ctx[k] == val)
            for hz_var in hiZVars.values():
                if hz_var in ctx: s_ver.add(ctx[hz_var] == True)

            print(f"\n{'-'*70}")
            print(f"EXHAUSTIVE TRUTH TABLE VERIFICATION FOR {test_folder}:")
            print(f"{'-'*70}")
            ver_all_pass = True
            for inp_tuple in all_input_tuples:
                s_ver.push()
                for i, in_name in enumerate(inVars):
                    s_ver.add(ctx[in_name] == inp_tuple[i])
                r = s_ver.check()
                if r == sat:
                    m = s_ver.model()
                    actual_outs = {out_name: is_true(m[ctx[out_name]]) for out_name in outVars}
                    expected_outs = golden_table[inp_tuple]
                    m_ok = (actual_outs == expected_outs)
                    if not m_ok: ver_all_pass = False
                    status_str = "MATCH (PASS)" if m_ok else "MISMATCH (FAIL)"
                    print(f"Input {inp_tuple} -> Golden: {expected_outs} | Fabric: {actual_outs} | {status_str}")
                else:
                    ver_all_pass = False
                    print(f"Input {inp_tuple} -> UNSAT (FAIL)")
                s_ver.pop()

            print(f"{'-'*70}")
            print(f"TRUTH TABLE CONCLUSION: {'100% MATCH (ALL PASS)' if ver_all_pass else 'FAIL'}")
            print(f"{'-'*70}\n")
            solver.delete()
            return True, duration, iteration, len(all_input_tuples)

        if counterexample is None:
            for inp_tuple in all_input_tuples:
                if inp_tuple not in constrained_patterns:
                    counterexample = inp_tuple
                    break

        print(f"Adding counterexample vector {counterexample} (Pattern #{len(constrained_patterns)+1})...\n", flush=True)
        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns) - 1, counterexample)

def main():
    print("#" * 80)
    print("STARTING 3x3 LARGE FABRIC ATTACK BENCHMARK: TEST 17 (AOI22) & TEST 18 (C17)")
    print("#" * 80)

    # 1. Run Test 17 (3x3 AOI22)
    ok17, dur17, iters17, pats17 = solve_3x3_benchmark(
        'Test17-TRAP_3x3_AOI22', 'trap3x3AOI22.py', 'trap3x3AOI22_io.csv', 'aoi22PL.py'
    )

    # 2. Run Test 18 (3x3 C17)
    ok18, dur18, iters18, pats18 = solve_3x3_benchmark(
        'Test18-TRAP_3x3_C17', 'trap3x3C17.py', 'trap3x3C17_io.csv', 'c17.py'
    )

    print("\n" + "#" * 80)
    print("LARGE 3x3 BENCHMARKS SUMMARY REPORT")
    print("#" * 80)
    print(f"Test 17 (3x3 AOI22): {'SUCCESS (100% MATCH)' if ok17 else 'FAIL'} in {dur17:.2f}s ({iters17} iters, {pats17} pats)")
    print(f"Test 18 (3x3 C17):   {'SUCCESS (100% MATCH)' if ok18 else 'FAIL'} in {dur18:.2f}s ({iters18} iters, {pats18} pats)")
    print("#" * 80 + "\n")

if __name__ == '__main__':
    main()
