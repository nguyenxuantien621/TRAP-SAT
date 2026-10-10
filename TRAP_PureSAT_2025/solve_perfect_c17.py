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

def solve_perfect_c17():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("PERFECT SOUND C17 SAT SOLVER (ALL 32 TEST VECTORS)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    key_set = set(keyVars)
    wire_vars = set(vars_dict.keys()) - key_set

    print(f"Total keys: {len(key_set)}, Wire/internal variables: {len(wire_vars)}")
    print(f"Total clauses: {len(clauses_list)}")
    sys.stdout.flush()

    compiled_clauses = []
    for c_str in clauses_list:
        try:
            compiled_clauses.append(compile(c_str, '<ast>', 'eval'))
        except Exception:
            pass

    def build_ctx(suffix):
        ctx = {}
        for k in vars_dict.keys():
            if k in key_set:
                ctx[k] = Bool(k) # ONLY keys are shared!
            else:
                ctx[k] = Bool(f"{k}{suffix}") # All wire/DL/cnt vars are pattern-specific!
        ctx['build_magnitude_comparator'] = build_magnitude_comparator
        ctx['is_greater_3bit'] = is_greater_3bit
        ctx['is_greater_4bit'] = is_greater_4bit
        ctx['is_greater_5bit'] = is_greater_5bit
        ctx['is_greater_6bit'] = is_greater_6bit
        ctx['is_greater_7bit'] = is_greater_7bit
        ctx['is_greater_8bit'] = is_greater_8bit
        ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})
        return ctx

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

    s = Solver()

    # Suppress primary input feedback
    for fk in feedback_keys:
        if fk in vars_dict:
            s.add(Bool(fk) == False)

    print("Instantiating all 32 truth table pattern copies...")
    sys.stdout.flush()

    pattern_idx = 0
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        pattern_idx += 1
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                        suffix = f"_p{pattern_idx}"
                        ctx_p = build_ctx(suffix)
                        
                        for code in compiled_clauses:
                            s.add(eval(code, ctx_p))
                        
                        s.add(ctx_p['pi1'] == p1)
                        s.add(ctx_p['pi2'] == p2)
                        s.add(ctx_p['pi3'] == p3)
                        s.add(ctx_p['pi6'] == p6)
                        s.add(ctx_p['pi7'] == p7)
                        s.add(ctx_p['po22'] == g22)
                        s.add(ctx_p['po23'] == g23)
                        s.add(ctx_p['VL47_1_1'] == True)
                        s.add(ctx_p['VL49_1_1'] == True)

    print(f"Solving complete 32-vector multi-copy system ({len(s.assertions())} assertions)...")
    sys.stdout.flush()
    t_s = time.time()
    res = s.check()
    print(f"Solver result: {res} in {time.time() - t_s:.2f}s")
    sys.stdout.flush()

    if res != sat:
        print("ERROR: Solver returned UNSAT!")
        return False

    model = s.model()
    clean_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row and len(row) > 1 and row[1].strip() == 'key':
                kname = row[0].strip()
                val = is_true(model[Bool(kname)]) if kname in key_set else False
                clean_rows.append([kname, str(val)])

    with open(key_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(clean_rows)

    print(f"Successfully extracted {len(clean_rows)} keys to {key_file} in {time.time() - t0:.2f}s!")
    sys.stdout.flush()
    return True

if __name__ == '__main__':
    solve_perfect_c17()
