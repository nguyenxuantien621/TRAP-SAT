import time
import csv
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

def solve_c17_minimal():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'

    print("=" * 80)
    print("DIRECT 32-VECTOR SAT SOLVE + MINIMAL KEY PRUNING (TEST 14 C17)")
    print("=" * 80)

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_names = set(keyVars) | {x for x in vars_dict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    dynamic_names = set(vars_dict.keys()) - static_names

    print(f"Total vars: {len(vars_dict)} (Static: {len(static_names)}, Dynamic: {len(dynamic_names)})")

    static_codes = []
    dynamic_codes = []
    for c_str in clauses_list:
        try:
            code = compile(c_str, '<ast>', 'eval')
            if 'is_greater_' in c_str or 'cnt' in c_str:
                static_codes.append(code)
            else:
                dynamic_codes.append(code)
        except Exception:
            pass

    def build_ctx(dyn_suffix):
        ctx = {}
        for k in vars_dict.keys():
            if k in static_names:
                ctx[k] = Bool(k)
            else:
                ctx[k] = Bool(f'{k}{dyn_suffix}')
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
    ctx_base = build_ctx('_base')

    # Add static acyclicity clauses
    for code in static_codes:
        s.add(eval(code, ctx_base))

    # Add feedback key suppression
    for fk in feedback_keys:
        if fk in ctx_base:
            s.add(ctx_base[fk] == False)

    # Add 32 patterns
    pattern_idx = 0
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        pattern_idx += 1
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                        ctx_p = build_ctx(f'_p{pattern_idx}')
                        for code in dynamic_codes:
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

    print(f"Setup completed with {len(s.assertions())} assertions in {time.time() - t0:.2f}s")
    print("Finding initial satisfying key model...")
    t_solve = time.time()
    res = s.check()
    print(f"Initial solve result: {res} in {time.time() - t_solve:.2f}s")

    if res != sat:
        print("ERROR: Initial solve returned UNSAT!")
        return False

    model = s.model()
    true_keys = []
    unique_key_names = sorted(list(set(keyVars)))
    for k in unique_key_names:
        if k in ctx_base and is_true(model[ctx_base[k]]):
            true_keys.append(k)

    print(f"Initial model has {len(true_keys)} active (True) keys out of {len(unique_key_names)}.")
    print("Pruning unneeded active keys to remove spurious loops and floating tracks...")

    # Greedy pruning
    pruned_count = 0
    final_key_vals = {k: False for k in unique_key_names}
    for k in true_keys:
        final_key_vals[k] = True

    for idx, k in enumerate(true_keys, 1):
        s.push()
        s.add(ctx_base[k] == False)
        if s.check() == sat:
            # We can safely turn this key OFF!
            s.pop()
            s.add(ctx_base[k] == False) # permanently fix to False
            final_key_vals[k] = False
            pruned_count += 1
        else:
            # Key is essential! Must remain True
            s.pop()

    essential_count = sum(1 for v in final_key_vals.values() if v)
    print(f"Pruning finished: pruned {pruned_count} keys, leaving {essential_count} essential active keys!")

    # Write extracted key
    extracted_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row:
                kname = row[0].strip()
                val = final_key_vals.get(kname, False)
                extracted_rows.append([kname, str(val)])

    out_csv = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(extracted_rows)

    print(f"Saved pruned extracted key ({len(extracted_rows)} rows) to {out_csv}")
    print(f"Total execution time: {time.time() - t0:.2f}s")
    return True

if __name__ == '__main__':
    solve_c17_minimal()
