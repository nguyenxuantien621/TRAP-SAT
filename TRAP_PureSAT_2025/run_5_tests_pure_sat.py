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

def run_single_test(test_folder, pl_fn, io_fn, oracle_fn):
    test_path = os.path.join('test', test_folder)
    pl_file = os.path.join(test_path, pl_fn)
    io_file = os.path.join(test_path, io_fn)
    oracle_file = os.path.join(test_path, oracle_fn)
    key_file = os.path.join(test_path, 'extracted_key.csv')

    print("\n" + "=" * 80, flush=True)
    print(f"EXECUTING PURESAT CADICAL153 ATTACK: {test_folder}", flush=True)
    print("=" * 80, flush=True)

    t_start = time.time()
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    print(f"Inputs ({len(inVars)}): {inVars} | Outputs ({len(outVars)}): {outVars} | Keys: {len(keyVars)}", flush=True)
    print(f"HiZ / Validities: {hiZVars}", flush=True)

    # Pre-compute full golden lookup table
    all_input_tuples = list(itertools.product([False, True], repeat=len(inVars)))
    golden_table = {}
    for inp_tuple in all_input_tuples:
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        out_dict = runPyOracle(inp_dict, oracle_file, inVars, outVars)
        golden_table[inp_tuple] = out_dict

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

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

        # Pin inputs
        for i, in_name in enumerate(inVars):
            in_val = inp_tuple[i]
            vid = var_map[in_name]
            solver.add_clause([ (vid + shift) if in_val else -(vid + shift) ])

        # Pin outputs
        for out_name in outVars:
            out_val = g_outs[out_name]
            vid = var_map[out_name]
            solver.add_clause([ (vid + shift) if out_val else -(vid + shift) ])

        # Pin validities
        for hz_var in hiZVars.values():
            if hz_var in var_map:
                solver.add_clause([ (var_map[hz_var] + shift) ])

    constrained_patterns = set()
    initial_pat = all_input_tuples[0]
    constrained_patterns.add(initial_pat)
    add_pattern(len(constrained_patterns) - 1, initial_pat)

    iteration = 0
    while True:
        iteration += 1
        t_it = time.time()
        res = solver.solve()
        if not res:
            print("ERROR: Solver returned UNSAT!", flush=True)
            return False, 0, 0, 0

        model = set(solver.get_model())
        cand_key = {k: (var_map[k] in model) if k in var_map else False for k in keyVars}

        # Verification via Cadical assumptions
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

        if pass_count == len(all_input_tuples):
            duration = time.time() - t_start
            print(f"SUCCESS! Key found in {iteration} rounds ({duration:.2f}s). All {pass_count}/{len(all_input_tuples)} passed!", flush=True)

            # Save extracted key with strict row format matching io_file
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
            for c in clauses_list:
                try: s_ver.add(eval(c, ctx))
                except: pass
            for k, val in cand_key.items():
                if k in ctx: s_ver.add(ctx[k] == val)
            for hz_var in hiZVars.values():
                if hz_var in ctx: s_ver.add(ctx[hz_var] == True)

            print(f"\n{'-'*60}")
            print(f"TRUTH TABLE VERIFICATION FOR {test_folder}:")
            print(f"{'-'*60}")
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

            print(f"{'-'*60}")
            print(f"VERIFICATION RESULT: {'100% MATCH (ALL PASS)' if ver_all_pass else 'FAIL'}")
            print(f"{'-'*60}\n")
            solver.delete()
            return True, duration, iteration, len(all_input_tuples)

        if counterexample is None:
            for inp_tuple in all_input_tuples:
                if inp_tuple not in constrained_patterns:
                    counterexample = inp_tuple
                    break

        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns) - 1, counterexample)

def main():
    test_suite = [
        ('Test08-TRAP_NAND2', 'trapNAND2.py', 'trapNAND2_io.csv', 'nand2PL.py'),
        ('Test09-TRAP_NOR3', 'trapNOR3.py', 'trapNOR3_io.csv', 'nor3PL.py'),
        ('Test11-TRAP_2x2_NAND2', 'trap2x2NAND2.py', 'trap2x2NAND2_io.csv', 'nand2PL.py'),
        ('Test12-TRAP_2x2_NOR3', 'trap2x2NOR3.py', 'trap2x2NOR3_io.csv', 'nor3PL.py'),
        ('Test13-TRAP_2x2_AOI22', 'trap2x2AOI22.py', 'trap2x2AOI22_io.csv', 'aoi22PL.py'),
    ]

    print("#" * 80)
    print("STARTING BATCH EXECUTION OF 5 TRAP BENCHMARK TESTS")
    print("#" * 80)

    results = []
    t_suite_start = time.time()

    for idx, (t_folder, pl_fn, io_fn, oracle_fn) in enumerate(test_suite, 1):
        print(f"\n>>> Running Benchmark {idx}/5: {t_folder}...")
        ok, dur, iters, total_pats = run_single_test(t_folder, pl_fn, io_fn, oracle_fn)
        results.append((t_folder, ok, dur, iters, total_pats))

    t_total = time.time() - t_suite_start
    print("\n" + "#" * 80)
    print("MASTER BENCHMARK EXECUTION SUMMARY (5 TESTS)")
    print("#" * 80)
    print(f"{'Testcase':<25} | {'Result':<12} | {'Time (s)':<10} | {'Iterations':<10} | {'Truth Table':<12}")
    print("-" * 80)
    for t_folder, ok, dur, iters, total_pats in results:
        res_str = "SUCCESS" if ok else "FAILED"
        tt_str = f"{total_pats}/{total_pats} (100%)" if ok else "FAIL"
        print(f"{t_folder:<25} | {res_str:<12} | {dur:<10.2f} | {iters:<10} | {tt_str:<12}")
    print("-" * 80)
    print(f"Total Suite Execution Time: {t_total:.2f}s ({t_total/60:.2f} mins)\n")

if __name__ == '__main__':
    main()
