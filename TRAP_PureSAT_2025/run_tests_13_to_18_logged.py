#!/usr/bin/env python3
'''
Automated Test Runner for Tests 13 to 18 with Instantaneous Real-Time Logging.
Suite:
  - Test 13: TRAP 2x2 AOI22
  - Test 14: TRAP 2x2 C17
  - Test 15: TRAP 2x1 AOI22
  - Test 16: TRAP 2x1 C17
  - Test 17: TRAP 3x3 AOI22
  - Test 18: TRAP 3x3 C17

Features:
  - Real-time logging written and flushed immediately upon completion of each test.
  - Dual logging to 'TRANSAT-main/logs' and 'TRAP_PureSAT_2025/logs'.
  - Full truth table verification via independent Z3 SMT solver.
'''

import os
import sys
import time
import csv
import datetime
import itertools
from z3 import *
import pysat.solvers

# Ensure TRAP_PureSAT_2025 is in python path
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

class MultiLogger:
    '''Logs to stdout and multiple log files simultaneously, flushing immediately.'''
    def __init__(self, filepaths):
        self.filepaths = filepaths
        self.files = []
        for fp in filepaths:
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            self.files.append(open(fp, 'w', encoding='utf-8'))

    def log(self, msg=""):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {msg}" if msg else ""
        print(formatted, flush=True)
        for f in self.files:
            f.write(formatted + "\n")
            f.flush()

    def close(self):
        for f in self.files:
            try:
                f.flush()
                f.close()
            except Exception:
                pass


def run_single_test(test_idx, total_tests, t_folder, pl_fn, io_fn, oracle_fn, suite_loggers):
    test_path = os.path.join(current_dir, 'test', t_folder)
    pl_file = os.path.join(test_path, pl_fn)
    io_file = os.path.join(test_path, io_fn)
    oracle_file = os.path.join(test_path, oracle_fn)
    key_file = os.path.join(test_path, 'extracted_key.csv')

    # Setup per-test logger in both logs directories
    log_name = f"{t_folder}.log"
    log_paths = [
        os.path.join(os.path.dirname(current_dir), 'logs', log_name),
        os.path.join(current_dir, 'logs', log_name)
    ]
    t_logger = MultiLogger(log_paths)

    def log_both(msg=""):
        t_logger.log(msg)
        for sl in suite_loggers:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted = f"[{timestamp}] [{t_folder}] {msg}" if msg else ""
            sl.write(formatted + "\n")
            sl.flush()

    log_both("=" * 80)
    log_both(f"STARTING BENCHMARK [{test_idx}/{total_tests}]: {t_folder}")
    log_both(f"PL File:     {pl_file}")
    log_both(f"IO File:     {io_file}")
    log_both(f"Oracle File: {oracle_file}")
    log_both("=" * 80)

    t_start = time.time()
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    log_both(f"Circuit Specifications:")
    log_both(f"  Inputs ({len(inVars)}):   {inVars}")
    log_both(f"  Outputs ({len(outVars)}): {outVars}")
    log_both(f"  Keys ({len(keyVars)}):       {len(set(keyVars))} unique ({len(keyVars)} total entries)")
    log_both(f"  HiZ / Validities: {hiZVars}")

    # Golden truth table pre-computation
    all_input_tuples = list(itertools.product([False, True], repeat=len(inVars)))
    golden_table = {}
    for inp_tuple in all_input_tuples:
        inp_dict = {inVars[i]: inp_tuple[i] for i in range(len(inVars))}
        out_dict = runPyOracle(inp_dict, oracle_file, inVars, outVars)
        golden_table[inp_tuple] = out_dict
    log_both(f"Pre-computed golden truth table for all {len(all_input_tuples)} input combinations.")

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    t0 = time.time()
    g = Goal()
    for c in clauses_list:
        try:
            g.add(eval(c, ctx))
        except Exception:
            pass

    t = Tactic('tseitin-cnf')
    cnf = t(g)[0]
    log_both(f"Tseitin CNF transformation completed in {time.time()-t0:.2f}s ({len(cnf)} clauses).")

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
    N_vars = len(var_map) + 1000

    solver = pysat.solvers.Cadical153()

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

    log_both(f"Initialized CEGIS loop with initial vector {initial_pat}...")

    iteration = 0
    attack_success = False
    cand_key = {}

    while True:
        iteration += 1
        t_it = time.time()
        log_both(f"  Iteration {iteration}: Solver clauses={solver.nof_clauses()}, vars={solver.nof_vars()}...")
        res = solver.solve()
        solve_dur = time.time() - t_it
        log_both(f"  Iteration {iteration}: CaDiCaL result={res} in {solve_dur:.2f}s")

        if not res:
            log_both(f"ERROR: Solver returned UNSAT at iteration {iteration}!")
            solver.delete()
            t_logger.close()
            return False, time.time() - t_start, iteration, 0, len(all_input_tuples)

        model = set(solver.get_model())
        cand_key = {k: (var_map[k] in model) if k in var_map else False for k in keyVars}

        # Verification via CaDiCaL assumptions
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
        log_both(f"  Verification: {pass_count}/{len(all_input_tuples)} passed in {time.time()-t_v:.2f}s")

        if pass_count == len(all_input_tuples):
            attack_success = True
            break

        if counterexample is None:
            for inp_tuple in all_input_tuples:
                if inp_tuple not in constrained_patterns:
                    counterexample = inp_tuple
                    break

        log_both(f"  Added counterexample: {counterexample} (Pattern #{len(constrained_patterns)+1})")
        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns) - 1, counterexample)

    solver.delete()
    total_dur = time.time() - t_start

    # Export key
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

    true_keys = sum(1 for r in clean_rows if r[1] == 'True')
    false_keys = sum(1 for r in clean_rows if r[1] == 'False')
    log_both(f"[+] Extracted key written to: {key_file} ({len(clean_rows)} rows: {true_keys} True, {false_keys} False)")

    # Independent Z3 truth table verification
    log_both("-" * 75)
    log_both(f"EXHAUSTIVE Z3 TRUTH TABLE VERIFICATION ({t_folder}):")
    log_both("-" * 75)

    s_ver = Solver()
    s_ver.set('timeout', 10000)
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

    z3_pass_count = 0
    for inp_tuple in all_input_tuples:
        s_ver.push()
        for i, in_name in enumerate(inVars):
            s_ver.add(ctx[in_name] == inp_tuple[i])
        r = s_ver.check()
        expected = golden_table[inp_tuple]
        vec_str = "".join(['1' if b else '0' for b in inp_tuple])
        if r == sat:
            m_z3 = s_ver.model()
            actual = {out_name: is_true(m_z3[ctx[out_name]]) for out_name in outVars}
            m_ok = (actual == expected)
            if m_ok:
                z3_pass_count += 1
            status_str = "MATCH (PASS)" if m_ok else "MISMATCH (FAIL)"
            log_both(f"  Vector {vec_str} ({inp_tuple}) -> Golden: {expected} | Fabric: {actual} | {status_str}")
        else:
            log_both(f"  Vector {vec_str} ({inp_tuple}) -> UNSAT (FAIL)")
        s_ver.pop()

    z3_all_pass = (z3_pass_count == len(all_input_tuples))
    log_both("-" * 75)
    log_both(f"TRUTH TABLE RESULT: {z3_pass_count}/{len(all_input_tuples)} PASS ({(z3_pass_count/len(all_input_tuples))*100:.1f}%)")
    log_both(f"BENCHMARK STATUS:   {'SUCCESS (100% MATCH)' if z3_all_pass else 'FAILED'}")
    log_both(f"Execution Time:     {total_dur:.2f}s ({iteration} CEGIS iterations)")
    log_both("=" * 80 + "\n")

    # Close test-specific logger immediately so log file is written and ready on disk
    t_logger.close()
    return z3_all_pass, total_dur, iteration, z3_pass_count, len(all_input_tuples)


def main():
    test_suite = [
        ('Test13-TRAP_2x2_AOI22', 'trap2x2AOI22.py', 'trap2x2AOI22_io.csv', 'aoi22PL.py'),
        ('Test14-TRAP_2x2_C17',   'trap2x2C17.py',   'trap2x2C17_io.csv',   'c17.py'),
        ('Test15-TRAP_2x1_AOI22', 'trap2x1AOI22.py', 'trap2x1AOI22_io.csv', 'aoi22PL.py'),
        ('Test16-TRAP_2x1_C17',   'trap2x1C17.py',   'trap2x1C17_io.csv',   'c17.py'),
        ('Test17-TRAP_3x3_AOI22', 'trap3x3AOI22.py', 'trap3x3AOI22_io.csv', 'aoi22PL.py'),
        ('Test18-TRAP_3x3_C17',   'trap3x3C17.py',   'trap3x3C17_io.csv',   'c17.py'),
    ]

    # Setup master suite loggers in both directories
    master_log_paths = [
        os.path.join(os.path.dirname(current_dir), 'logs', 'run_tests_13_to_18_master.log'),
        os.path.join(current_dir, 'logs', 'run_tests_13_to_18_master.log')
    ]
    suite_files = []
    for p in master_log_paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        suite_files.append(open(p, 'w', encoding='utf-8'))

    def log_master(msg=""):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {msg}" if msg else ""
        print(formatted, flush=True)
        for f in suite_files:
            f.write(formatted + "\n")
            f.flush()

    log_master("#" * 80)
    log_master("AUTOMATED EXECUTION & LOGGING: TRAP BENCHMARK SUITE (TESTS 13 TO 18)")
    log_master(f"Total benchmarks: {len(test_suite)}")
    log_master(f"Master log location 1: {master_log_paths[0]}")
    log_master(f"Master log location 2: {master_log_paths[1]}")
    log_master("#" * 80)

    results = []
    t_all_start = time.time()

    for idx, (t_folder, pl_fn, io_fn, oracle_fn) in enumerate(test_suite, 1):
        log_master(f"\n>>> [DISPATCHING {idx}/{len(test_suite)}]: {t_folder}...")
        ok, dur, iters, pass_cnt, total_pats = run_single_test(
            idx, len(test_suite), t_folder, pl_fn, io_fn, oracle_fn, suite_files
        )
        results.append((t_folder, ok, dur, iters, pass_cnt, total_pats))

        # Immediately log per-test completion to master log
        log_master(f">>> [FINISHED {idx}/{len(test_suite)}]: {t_folder} -> {'SUCCESS' if ok else 'FAIL'} in {dur:.2f}s ({pass_cnt}/{total_pats} vectors)")
        log_master(f">>> Log saved: logs/{t_folder}.log")

    total_time = time.time() - t_all_start
    log_master("\n" + "#" * 80)
    log_master("FINAL SUITE SUMMARY REPORT: TESTS 13 TO 18")
    log_master("#" * 80)
    log_master(f"{'Benchmark':<25} | {'Result':<12} | {'Time (s)':<10} | {'Iters':<8} | {'Truth Table':<12}")
    log_master("-" * 80)
    for t_folder, ok, dur, iters, pass_cnt, total_pats in results:
        res_str = "SUCCESS" if ok else "FAILED"
        tt_str = f"{pass_cnt}/{total_pats} (100%)" if ok else f"{pass_cnt}/{total_pats}"
        log_master(f"{t_folder:<25} | {res_str:<12} | {dur:<10.2f} | {iters:<8} | {tt_str:<12}")
    log_master("-" * 80)
    all_ok = all(r[1] for r in results)
    log_master(f"OVERALL STATUS: {'ALL 6 BENCHMARKS PASSED 100%' if all_ok else 'SOME BENCHMARKS FAILED'}")
    log_master(f"Total Execution Time: {total_time:.2f}s ({total_time/60:.2f} minutes)")
    log_master("#" * 80 + "\n")

    for f in suite_files:
        try:
            f.flush()
            f.close()
        except Exception:
            pass

if __name__ == '__main__':
    main()
