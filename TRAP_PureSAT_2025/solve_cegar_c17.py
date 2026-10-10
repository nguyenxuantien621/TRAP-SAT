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

def solve_cegar_c17():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("CEGAR EXACT SAT ATTACK ON TEST 14 (TRAP 2x2 C17)")
    print("=" * 80)

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    key_set = set(keyVars)
    wire_vars = set(vars_dict.keys()) - key_set

    print(f"Key variables: {len(key_set)}, Wire variables: {len(wire_vars)}")
    print(f"Total base clauses: {len(clauses_list)}")

    compiled_clauses = []
    for c_str in clauses_list:
        try:
            compiled_clauses.append(compile(c_str, '<ast>', 'eval'))
        except Exception:
            pass

    def build_pattern_ctx(suffix):
        ctx = {}
        for k in vars_dict.keys():
            if k in key_set:
                ctx[k] = Bool(k) # Shared key!
            else:
                ctx[k] = Bool(f"{k}{suffix}") # Pattern-specific wire/DL/cnt
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
    eval_ctx = {k: Bool(k) for k in vars_dict.keys()}
    eval_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    eval_ctx['is_greater_3bit'] = is_greater_3bit
    eval_ctx['is_greater_4bit'] = is_greater_4bit
    eval_ctx['is_greater_5bit'] = is_greater_5bit
    eval_ctx['is_greater_6bit'] = is_greater_6bit
    eval_ctx['is_greater_7bit'] = is_greater_7bit
    eval_ctx['is_greater_8bit'] = is_greater_8bit
    eval_ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})
    
    base_eval_clauses = [eval(code, eval_ctx) for code in compiled_clauses]

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

    # CEGAR Solver
    s_master = Solver()

    # Feedback suppression
    for fk in feedback_keys:
        if fk in eval_ctx:
            s_master.add(Bool(fk) == False)

    # Add initial seed patterns
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
        # Add any newly identified patterns to master solver
        for p in active_patterns:
            if p not in added_patterns:
                added_patterns.add(p)
                p1, p2, p3, p6, p7 = p
                g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
                suffix = f"_p_{int(p1)}{int(p2)}{int(p3)}{int(p6)}{int(p7)}"
                ctx_p = build_pattern_ctx(suffix)
                
                print(f"Adding pattern constraint: {p} -> ({int(g22)}, {int(g23)})")
                for code in compiled_clauses:
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
        t_s = time.time()
        res = s_master.check()
        print(f"Master solve result: {res} in {time.time() - t_s:.2f}s")

        if res != sat:
            print("ERROR: Master solver returned UNSAT!")
            return False

        model = s_master.model()
        cur_key = {}
        for k in key_set:
            cur_key[k] = is_true(model[Bool(k)])

        print("Verifying candidate key on full 32-vector truth table...")
        fails = verify_key(cur_key)
        passed = 32 - len(fails)
        print(f"Truth Table Result: {passed}/32 PASS (Fails: {len(fails)})")

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
            return True

        # Add failed patterns as counterexamples
        active_patterns.extend(fails[:3]) # Add up to 3 failing patterns per round
        iteration += 1

if __name__ == '__main__':
    solve_cegar_c17()
