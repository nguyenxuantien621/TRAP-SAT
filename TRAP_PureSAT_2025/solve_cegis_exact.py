import time
import csv
import sys
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

def run_cegis_exact():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("CEGIS DEOBFUSCATION ATTACK ON TEST 14 (TRAP 2x2 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_names = set(keyVars) | {x for x in vars_dict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp') or x.startswith('VL') or x.startswith('VC')}
    dyn_names = set(vars_dict.keys()) - static_names

    print(f"Total variables: {len(vars_dict)} (Static: {len(static_names)}, Dynamic: {len(dyn_names)})")
    sys.stdout.flush()

    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    # Partition clauses into static (acyclicity) vs dynamic (functional)
    static_codes = []
    dynamic_codes = []
    for c in clauses_list:
        if 'is_greater_' in c or 'cnt' in c:
            static_codes.append(compile(c, '<ast>', 'eval'))
        else:
            dynamic_codes.append(compile(c, '<ast>', 'eval'))

    print(f"Partitioned clauses: {len(static_codes)} static, {len(dynamic_codes)} dynamic")
    sys.stdout.flush()

    # Pre-build verification clauses
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

    # 1. Base static context & static clauses (added ONCE)
    static_ctx = dict(exec_ctx_base)
    for v in vars_dict.keys():
        static_ctx[v] = Bool(v)

    for code in static_codes:
        s.add(eval(code, static_ctx))

    s.add(static_ctx['VL47_1_1'] == True)
    s.add(static_ctx['VL49_1_1'] == True)

    def add_pattern(p_idx, p1, p2, p3, p6, p7):
        pat_ctx = dict(static_ctx)
        for v in dyn_names:
            pat_ctx[v] = Bool(f"{v}_p{p_idx}")
        for code in dynamic_codes:
            s.add(eval(code, pat_ctx))
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
        s.add(pat_ctx['pi1'] == p1)
        s.add(pat_ctx['pi2'] == p2)
        s.add(pat_ctx['pi3'] == p3)
        s.add(pat_ctx['pi6'] == p6)
        s.add(pat_ctx['pi7'] == p7)
        s.add(pat_ctx['po22'] == g22)
        s.add(pat_ctx['po23'] == g23)

    all_32_inputs = []
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        all_32_inputs.append((p1, p2, p3, p6, p7))

    constrained_patterns = set()
    initial_pat = (False, False, False, False, False)
    constrained_patterns.add(initial_pat)
    add_pattern(len(constrained_patterns), *initial_pat)

    print(f"Starting CEGIS loop with initial vector {initial_pat}...")
    sys.stdout.flush()

    iteration = 0
    while True:
        iteration += 1
        t_iter = time.time()
        print(f"\n--- Iteration {iteration} (Patterns: {len(constrained_patterns)}, Assertions: {len(s.assertions())}) ---")
        sys.stdout.flush()

        res = s.check()
        print(f"Solver result: {res} in {time.time() - t_iter:.2f}s")
        sys.stdout.flush()

        if res != sat:
            print("ERROR: Synthesis solver returned UNSAT!")
            return False

        m = s.model()
        cand_key = {}
        for k in keyVars:
            cand_key[k] = is_true(m[Bool(k)])

        # Verify candidate key against all 32 vectors
        t_v = time.time()
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

        print(f"Candidate passed {pass_count}/32 vectors (verification took {time.time() - t_v:.2f}s)")
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

            print(f"Extracted key saved to {key_file} ({len(clean_rows)} key rows)")
            print(f"Total Attack Time: {time.time() - t_start:.2f}s")
            return True

        if counterexample is None:
            for vec in all_32_inputs:
                if vec not in constrained_patterns:
                    counterexample = vec
                    break

        print(f"Adding counterexample vector {counterexample} to synthesis solver...")
        sys.stdout.flush()
        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns), *counterexample)

if __name__ == '__main__':
    run_cegis_exact()
