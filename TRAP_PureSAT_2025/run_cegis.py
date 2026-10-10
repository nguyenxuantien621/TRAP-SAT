import time
import csv
import sys
import re
from z3 import *

from src.pysatAttack import (
    readZ3pl, parsePL,
    build_magnitude_comparator,
    is_greater_3bit, is_greater_4bit, is_greater_5bit,
    is_greater_6bit, is_greater_7bit, is_greater_8bit
)

def compute_golden_c17(pi1, pi2, pi3, pi6, pi7):
    nand1 = not (pi1 and pi3)
    nand2 = not (pi3 and pi6)
    nand5 = not (nand2 and pi7)
    nand6 = not (nand2 and pi2)
    nand3 = not (nand1 and nand6)
    nand4 = not (nand6 and nand5)
    return nand3, nand4

def run_cegis():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("CEGIS ITERATIVE SOLVER (COUNTEREXAMPLE-GUIDED INDUCTIVE SYNTHESIS)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_prefix = ('DL', 'DC', 'cnt', 'isInp', 'VL', 'VC')
    key_set = set(keyVars)
    static_set = key_set | {k for k in vars_dict if any(k.startswith(p) for p in static_prefix)}
    dyn_vars = set(vars_dict.keys()) - static_set

    print(f"Total vars: {len(vars_dict)} (Static: {len(static_set)}, Dynamic: {len(dyn_vars)})")
    sys.stdout.flush()

    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    # Pre-compile AST
    static_clauses_code = []
    dyn_clauses_code = []

    for c in clauses_list:
        tokens = set(re.findall(r'\b[A-Za-z0-9_]+\b', c))
        vars_in_c = tokens.intersection(vars_dict.keys())
        dyn_in_c = vars_in_c.intersection(dyn_vars)
        code = compile(c, '<ast>', 'eval')
        if dyn_in_c:
            dyn_clauses_code.append(code)
        else:
            static_clauses_code.append(code)

    print(f"Partitioned: {len(static_clauses_code)} pure static, {len(dyn_clauses_code)} dynamic-dependent")
    sys.stdout.flush()

    # Pre-build base verification solver
    base_eval_ctx = {k: Bool(k) for k in vars_dict.keys()}
    base_eval_ctx.update(exec_ctx_base)
    base_eval_clauses = []
    for c_str in clauses_list:
        try:
            base_eval_clauses.append(eval(c_str, base_eval_ctx))
        except Exception:
            pass

    # Synthesis Solver
    s = Solver()

    # 1. Add static clauses ONCE
    static_ctx = dict(exec_ctx_base)
    for v in static_set:
        static_ctx[v] = Bool(v)
    for v in dyn_vars:
        static_ctx[v] = Bool(v)

    for code in static_clauses_code:
        s.add(eval(code, static_ctx))

    # Suppress primary input feedback keys
    feedback_keys = [
        'L31_0_0L41_0_0', 'L31_0_0L44_0_0', 'L31_0_0L47_0_0',
        'L32_0_0L42_0_0', 'L32_0_0L45_0_0', 'L32_0_0L48_0_0',
        'L33_0_0L43_0_0', 'L33_0_0L46_0_0', 'L33_0_0L49_0_0',
        'L34_0_0L41_0_0', 'L34_0_0L44_0_0', 'L34_0_0L47_0_0',
        'L35_0_0L42_0_0', 'L35_0_0L45_0_0', 'L35_0_0L48_0_0',
        'L36_0_0L43_0_0', 'L36_0_0L46_0_0', 'L36_0_0L49_0_0',
        'L37_0_0L41_0_0', 'L37_0_0L44_0_0', 'L37_0_0L47_0_0',
        'L38_0_0L42_0_0', 'L38_0_0L45_0_0', 'L38_0_0L48_0_0',
        'L39_0_0L43_0_0', 'L39_0_0L46_0_0', 'L39_0_0L49_0_0'
    ]
    for fk in feedback_keys:
        if fk in static_ctx:
            s.add(Not(static_ctx[fk]))

    if 'VL47_1_1' in static_ctx:
        s.add(static_ctx['VL47_1_1'] == True)
    if 'VL49_1_1' in static_ctx:
        s.add(static_ctx['VL49_1_1'] == True)

    def add_pattern_to_synthesis(p_idx, p1, p2, p3, p6, p7):
        p_prefix = f"pat{p_idx}"
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
        pat_ctx = dict(static_ctx)
        for v in dyn_vars:
            pat_ctx[v] = Bool(f"{v}_{p_prefix}")
        for code in dyn_clauses_code:
            s.add(eval(code, pat_ctx))
        s.add(pat_ctx['pi1'] == p1)
        s.add(pat_ctx['pi2'] == p2)
        s.add(pat_ctx['pi3'] == p3)
        s.add(pat_ctx['pi6'] == p6)
        s.add(pat_ctx['pi7'] == p7)
        s.add(pat_ctx['po22'] == g22)
        s.add(pat_ctx['po23'] == g23)

    # All 32 truth table inputs
    all_32_inputs = []
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        all_32_inputs.append((p1, p2, p3, p6, p7))

    # Start with initial pattern (0,0,0,0,0)
    constrained_patterns = set()
    initial_pat = (False, False, False, False, False)
    constrained_patterns.add(initial_pat)
    add_pattern_to_synthesis(0, *initial_pat)

    print(f"Starting CEGIS loop with initial vector {initial_pat}...")
    sys.stdout.flush()

    iteration = 0
    while True:
        iteration += 1
        t_iter = time.time()
        print(f"\n--- Iteration {iteration} (Constrained patterns: {len(constrained_patterns)}) ---")
        sys.stdout.flush()

        res = s.check()
        if res != sat:
            print("Synthesis solver returned UNSAT! Backtracking...")
            return False

        m = s.model()
        # Extract candidate key
        cand_key = {}
        for k in keyVars:
            cand_key[k] = is_true(m[Bool(k)])

        print(f"Found candidate key in {time.time() - t_iter:.2f}s. Verifying against 32 vectors...")
        sys.stdout.flush()

        # Build verification solver for candidate key
        v_solver = Solver()
        for c in base_eval_clauses:
            v_solver.add(c)
        for k, val in cand_key.items():
            if k in base_eval_ctx:
                v_solver.add(base_eval_ctx[k] == val)
        v_solver.add(base_eval_ctx['VL47_1_1'] == True)
        v_solver.add(base_eval_ctx['VL49_1_1'] == True)

        counterexample = None
        pass_count = 0

        for vec in all_32_inputs:
            p1, p2, p3, p6, p7 = vec
            g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
            v_solver.push()
            v_solver.add(base_eval_ctx['pi1'] == p1)
            v_solver.add(base_eval_ctx['pi2'] == p2)
            v_solver.add(base_eval_ctx['pi3'] == p3)
            v_solver.add(base_eval_ctx['pi6'] == p6)
            v_solver.add(base_eval_ctx['pi7'] == p7)

            if v_solver.check() == sat:
                vm = v_solver.model()
                f22 = is_true(vm[base_eval_ctx['po22']])
                f23 = is_true(vm[base_eval_ctx['po23']])
                if (f22 == g22) and (f23 == g23):
                    pass_count += 1
                else:
                    if counterexample is None and vec not in constrained_patterns:
                        counterexample = vec
            else:
                if counterexample is None and vec not in constrained_patterns:
                    counterexample = vec
            v_solver.pop()

        print(f"Candidate passed {pass_count}/32 vectors!")
        sys.stdout.flush()

        if pass_count == 32:
            print("\n" + "=" * 80)
            print("SUCCESS! PERFECT KEY FOUND MATCHING ALL 32/32 VECTORS!")
            print("=" * 80)
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

            print(f"Saved {len(clean_rows)} keys to {key_file} in {time.time() - t0:.2f}s total.")
            return True

        if counterexample is None:
            # Pick any unconstrained vector
            for vec in all_32_inputs:
                if vec not in constrained_patterns:
                    counterexample = vec
                    break

        print(f"Adding counterexample vector {counterexample} as new constraint...")
        sys.stdout.flush()
        constrained_patterns.add(counterexample)
        add_pattern_to_synthesis(len(constrained_patterns), *counterexample)

if __name__ == '__main__':
    run_cegis()
