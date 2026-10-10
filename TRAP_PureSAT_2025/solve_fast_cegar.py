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

def solve_fast_cegar():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("LIGHTNING FAST CEGAR SAT SOLVER FOR TEST 14 (TRAP 2x2 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_names = set(keyVars) | {x for x in vars_dict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    dynamic_names = set(vars_dict.keys()) - static_names

    print(f"Static variables (shared): {len(static_names)}, Dynamic variables (per-pattern): {len(dynamic_names)}")

    static_codes = []
    dynamic_codes = []
    for c_str in clauses_list:
        try:
            code = compile(c_str, '<ast>', 'eval')
            if 'is_greater_' in c_str or 'cnt' in c_str or c_str.startswith('isInp') or ('isInp' in c_str and '==' not in c_str and 'Or(' not in c_str):
                static_codes.append(code)
            else:
                dynamic_codes.append(code)
        except Exception:
            pass

    print(f"Static clauses (added once): {len(static_codes)}, Dynamic clauses: {len(dynamic_codes)}")
    sys.stdout.flush()

    def build_ctx(dyn_suffix):
        ctx = {}
        for k in vars_dict.keys():
            if k in static_names:
                ctx[k] = Bool(k)
            else:
                ctx[k] = Bool(f"{k}{dyn_suffix}")
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

    # Pre-build verification base clauses
    eval_ctx = build_ctx('')
    all_compiled = static_codes + dynamic_codes
    base_eval_clauses = [eval(code, eval_ctx) for code in all_compiled]

    def verify_key(key_dict):
        s_ver = Solver()
        for c in base_eval_clauses:
            s_ver.add(c)
        for k, v in key_dict.items():
            if k in eval_ctx:
                s_ver.add(eval_ctx[k] == v)
        s_ver.add(eval_ctx['VL47_1_1'] == True)
        s_ver.add(eval_ctx['VL49_1_1'] == True)
        
        fails = []
        for p1 in [False, True]:
            for p2 in [False, True]:
                for p3 in [False, True]:
                    for p6 in [False, True]:
                        for p7 in [False, True]:
                            g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                            s_ver.push()
                            s_ver.add(eval_ctx['pi1'] == p1)
                            s_ver.add(eval_ctx['pi2'] == p2)
                            s_ver.add(eval_ctx['pi3'] == p3)
                            s_ver.add(eval_ctx['pi6'] == p6)
                            s_ver.add(eval_ctx['pi7'] == p7)
                            if s_ver.check() == sat:
                                m = s_ver.model()
                                f22 = is_true(m[eval_ctx['po22']])
                                f23 = is_true(m[eval_ctx['po23']])
                                if not ((f22 == g22) and (f23 == g23)):
                                    fails.append((p1, p2, p3, p6, p7))
                            else:
                                fails.append((p1, p2, p3, p6, p7))
                            s_ver.pop()
        return fails

    # Initialize master solver
    s_master = Solver()
    ctx_static = build_ctx('')

    # Add static clauses ONLY ONCE
    for code in static_codes:
        s_master.add(eval(code, ctx_static))

    for fk in feedback_keys:
        if fk in ctx_static:
            s_master.add(ctx_static[fk] == False)

    # Initial seed patterns
    active_patterns = [
        (False, False, False, False, False),
        (True, False, False, False, False),
        (False, True, False, False, False),
        (False, False, True, False, False),
        (False, False, False, True, False),
        (False, False, False, False, True),
        (True, True, True, True, True),
    ]

    added_patterns = set()
    iteration = 1

    while True:
        print(f"\n--- CEGAR Iteration #{iteration} ---")
        sys.stdout.flush()

        for p in active_patterns:
            if p not in added_patterns:
                added_patterns.add(p)
                p1, p2, p3, p6, p7 = p
                g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                suffix = f"_p_{int(p1)}{int(p2)}{int(p3)}{int(p6)}{int(p7)}"
                ctx_p = build_ctx(suffix)
                
                print(f"Adding pattern constraint: {p} -> ({int(g22)}, {int(g23)})")
                for code in dynamic_codes:
                    s_master.add(eval(code, ctx_p))
                
                s_master.add(ctx_p['pi1'] == p1)
                s_master.add(ctx_p['pi2'] == p2)
                s_master.add(ctx_p['pi3'] == p3)
                s_master.add(ctx_p['pi6'] == p6)
                s_master.add(ctx_p['pi7'] == p7)
                s_master.add(ctx_p['po22'] == g22)
                s_master.add(ctx_p['po23'] == g23)
                s_master.add(ctx_p['VL47_1_1'] == True)
                s_master.add(ctx_p['VL49_1_1'] == True)

        print(f"Solving master solver with {len(added_patterns)} patterns ({len(s_master.assertions())} assertions)...")
        sys.stdout.flush()
        t_s = time.time()
        res = s_master.check()
        print(f"Master solve result: {res} in {time.time() - t_s:.2f}s")
        sys.stdout.flush()

        if res != sat:
            print("ERROR: Master solver returned UNSAT!")
            return False

        model = s_master.model()
        cur_key = {}
        for k in keyVars:
            if k in ctx_static:
                cur_key[k] = is_true(model[ctx_static[k]])

        print("Verifying candidate key on full 32-vector truth table...")
        sys.stdout.flush()
        fails = verify_key(cur_key)
        passed = 32 - len(fails)
        print(f"Truth Table Result: {passed}/32 PASS (Fails: {len(fails)})")
        sys.stdout.flush()

        if len(fails) == 0:
            print("\n" + "=" * 80)
            print("CONGRATULATIONS: 32/32 TEST CASES MATCH 100%! KEY IS PERFECTLY VALID!")
            print("=" * 80)
            
            clean_rows = []
            with open(io_file, 'r') as f:
                for row in csv.reader(f):
                    if row and len(row) > 1 and row[1].strip() == 'key':
                        kname = row[0].strip()
                        val = cur_key.get(kname, False)
                        clean_rows.append([kname, str(val)])

            with open(key_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(clean_rows)

            print(f"Saved verified extracted key ({len(clean_rows)} rows) to {key_file}")
            print(f"Total time elapsed: {time.time() - t_start:.2f}s")
            sys.stdout.flush()
            return True

        # Add ALL failing patterns as counterexamples for immediate convergence!
        active_patterns.extend(fails)
        iteration += 1

if __name__ == '__main__':
    solve_fast_cegar()
