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

def solve_exact_32():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("EXACT 32-PATTERN SOLVER WITH STATIC/DYNAMIC PARTITIONING")
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

    # Pre-parse clauses into AST
    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    # Partition clauses
    static_clauses_code = []
    dyn_clauses_info = [] # (code, set of dyn vars)

    for c in clauses_list:
        tokens = set(re.findall(r'\b[A-Za-z0-9_]+\b', c))
        vars_in_c = tokens.intersection(vars_dict.keys())
        dyn_in_c = vars_in_c.intersection(dyn_vars)
        code = compile(c, '<ast>', 'eval')
        if dyn_in_c:
            dyn_clauses_info.append((code, dyn_in_c))
        else:
            static_clauses_code.append(code)

    print(f"Clause breakdown: {len(static_clauses_code)} pure static, {len(dyn_clauses_info)} dynamic-dependent")
    sys.stdout.flush()

    s = Solver()

    # 1. Instantiate static context & add static clauses (ONCE!)
    static_ctx = dict(exec_ctx_base)
    for v in static_set:
        static_ctx[v] = Bool(v)
    for v in dyn_vars:
        static_ctx[v] = Bool(v) # default fallback

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

    # Validities on output tile
    if 'VL47_1_1' in static_ctx:
        s.add(static_ctx['VL47_1_1'] == True)
    if 'VL49_1_1' in static_ctx:
        s.add(static_ctx['VL49_1_1'] == True)

    # 2. Instantiate all 32 dynamic patterns
    pattern_idx = 0
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        p_prefix = f"p{pattern_idx}"
                        pattern_idx += 1
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

                        # Create pattern-specific context
                        pat_ctx = dict(static_ctx)
                        for v in dyn_vars:
                            pat_ctx[v] = Bool(f"{v}_{p_prefix}")

                        for code, _ in dyn_clauses_info:
                            s.add(eval(code, pat_ctx))

                        # Fix inputs for this pattern
                        s.add(pat_ctx['pi1'] == p1)
                        s.add(pat_ctx['pi2'] == p2)
                        s.add(pat_ctx['pi3'] == p3)
                        s.add(pat_ctx['pi6'] == p6)
                        s.add(pat_ctx['pi7'] == p7)

                        # Fix outputs for this pattern
                        s.add(pat_ctx['po22'] == g22)
                        s.add(pat_ctx['po23'] == g23)

    print(f"Total assertions in Z3: {len(s.assertions())}")
    print("Solving full 32-vector system with Z3...")
    sys.stdout.flush()

    t_solve = time.time()
    res = s.check()
    solve_duration = time.time() - t_solve
    print(f"Z3 Result: {res} in {solve_duration:.2f}s!")
    sys.stdout.flush()

    if res != sat:
        print("ERROR: Z3 returned UNSAT!")
        return False

    m = s.model()
    clean_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row and len(row) > 1 and row[1].strip() == 'key':
                kname = row[0].strip()
                k_sym = Bool(kname)
                val = is_true(m[k_sym])
                clean_rows.append([kname, str(val)])

    with open(key_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(clean_rows)

    print(f"Extracted {len(clean_rows)} keys to {key_file} in {time.time() - t0:.2f}s total.")
    return True

if __name__ == '__main__':
    solve_exact_32()
