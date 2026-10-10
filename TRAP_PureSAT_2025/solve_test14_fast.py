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

def solve_test14():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'

    print("=" * 80)
    print("OPTIMIZED IN-MEMORY SAT ATTACK ON TEST 14 (TRAP 2x2 C17)")
    print("=" * 80)

    # 1. Read PL & IO CSV
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_names = set(keyVars) | {x for x in vars_dict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    dynamic_names = set(vars_dict.keys()) - static_names

    print(f"Total variables: {len(vars_dict)} (Static: {len(static_names)}, Dynamic: {len(dynamic_names)})")

    # Separate and compile static vs dynamic clauses
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

    print(f"Static clauses: {len(static_codes)} (acyclicity), Dynamic clauses: {len(dynamic_codes)} (functional)")

    def build_ctx(dyn_suffix, key_suffix=''):
        ctx = {}
        for k in vars_dict.keys():
            if k in static_names:
                ctx[k] = Bool(f"{k}{key_suffix}")
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

    print("Initializing Miter Solver...")
    miter_solver = Solver()

    # Contexts for Miter copy 1 and copy 2
    ctx_m1 = build_ctx('_m1', '_1')
    ctx_m2 = build_ctx('_m2', '_2')

    # Add static acyclicity clauses ONLY ONCE for K1 and K2
    for code in static_codes:
        miter_solver.add(eval(code, ctx_m1))
        miter_solver.add(eval(code, ctx_m2))

    # Add initial dynamic clauses for m1 and m2
    for code in dynamic_codes:
        miter_solver.add(eval(code, ctx_m1))
        miter_solver.add(eval(code, ctx_m2))

    # Feedback key suppression
    for fk in feedback_keys:
        if fk in ctx_m1:
            miter_solver.add(ctx_m1[fk] == False)
            miter_solver.add(ctx_m2[fk] == False)

    # Tie inputs of copy 1 and 2 to common search inputs
    for inv in inVars:
        miter_solver.add(ctx_m1[inv] == Bool(inv))
        miter_solver.add(ctx_m2[inv] == Bool(inv))

    # Enable output validity
    miter_solver.add(ctx_m1['VL47_1_1'] == True)
    miter_solver.add(ctx_m1['VL49_1_1'] == True)
    miter_solver.add(ctx_m2['VL47_1_1'] == True)
    miter_solver.add(ctx_m2['VL49_1_1'] == True)

    # Miter output comparator
    diff_terms = [
        Xor(ctx_m1[outv], ctx_m2[outv]) for outv in outVars
    ]
    miter_solver.add(Or(*diff_terms))

    print(f"Miter initialized with {len(miter_solver.assertions())} assertions.")

    all_dips = []
    round_num = 1
    max_rounds = 35

    while round_num <= max_rounds:
        t_r = time.time()
        print(f"Round #{round_num}: Checking Miter satisfiability...", end=' ', flush=True)
        res = miter_solver.check()
        print(f"Result: {res} ({time.time() - t_r:.2f}s)")
        
        if res != sat:
            print(f"-> Miter reached UNSAT! Attack search finished in {round_num - 1} rounds.")
            break

        model = miter_solver.model()
        dip = {inv: is_true(model[Bool(inv)]) for inv in inVars}
        print(f"  -> Extracted DIP #{round_num}: {dip}")
        all_dips.append(dip)

        g22, g23 = compute_golden_c17(dip['pi1'], dip['pi2'], dip['pi3'], dip['pi6'], dip['pi7'])
        oracle_out = {'po22': g22, 'po23': g23}
        print(f"  -> Golden Oracle output: {oracle_out}")

        # Add ONLY dynamic clauses for DIP copy 1 and copy 2
        ctx_cp1 = build_ctx(f'_cp{round_num}_1', '_1')
        ctx_cp2 = build_ctx(f'_cp{round_num}_2', '_2')

        for code in dynamic_codes:
            miter_solver.add(eval(code, ctx_cp1))
            miter_solver.add(eval(code, ctx_cp2))

        for inv in inVars:
            miter_solver.add(ctx_cp1[inv] == dip[inv])
            miter_solver.add(ctx_cp2[inv] == dip[inv])

        for outv, oval in oracle_out.items():
            miter_solver.add(ctx_cp1[outv] == oval)
            miter_solver.add(ctx_cp2[outv] == oval)

        miter_solver.add(ctx_cp1['VL47_1_1'] == True)
        miter_solver.add(ctx_cp1['VL49_1_1'] == True)
        miter_solver.add(ctx_cp2['VL47_1_1'] == True)
        miter_solver.add(ctx_cp2['VL49_1_1'] == True)

        # Block this DIP
        block_terms = [Bool(inv) != val for inv, val in dip.items()]
        miter_solver.add(Or(*block_terms))

        round_num += 1

    # Solve final key
    print("\nSolving Final Key from accumulated constraints...")
    final_solver = Solver()
    ctx_final_base = build_ctx('_f0', '')
    
    # Add static clauses once
    for code in static_codes:
        final_solver.add(eval(code, ctx_final_base))

    for fk in feedback_keys:
        if fk in ctx_final_base:
            final_solver.add(ctx_final_base[fk] == False)

    for i, dip in enumerate(all_dips, 1):
        ctx_fcp = build_ctx(f'_fcp{i}', '')
        for code in dynamic_codes:
            final_solver.add(eval(code, ctx_fcp))
        for inv in inVars:
            final_solver.add(ctx_fcp[inv] == dip[inv])
        g22, g23 = compute_golden_c17(dip['pi1'], dip['pi2'], dip['pi3'], dip['pi6'], dip['pi7'])
        final_solver.add(ctx_fcp['po22'] == g22)
        final_solver.add(ctx_fcp['po23'] == g23)
        final_solver.add(ctx_fcp['VL47_1_1'] == True)
        final_solver.add(ctx_fcp['VL49_1_1'] == True)

    t_f = time.time()
    print("Checking final key satisfiability...", end=' ', flush=True)
    final_res = final_solver.check()
    print(f"Result: {final_res} ({time.time() - t_f:.2f}s)")

    if final_res == sat:
        m = final_solver.model()
        extracted_rows = []
        with open(io_file, 'r') as f:
            for row in csv.reader(f):
                if row and len(row) > 1 and row[1].strip() == 'key':
                    kname = row[0].strip()
                    val = is_true(m[ctx_final_base[kname]]) if kname in ctx_final_base else False
                    extracted_rows.append([kname, str(val)])

        out_csv = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'
        with open(out_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(extracted_rows)

        print(f"\nSUCCESS: Extracted Key saved to {out_csv} ({len(extracted_rows)} key rows)")
        print(f"Total Execution Time: {time.time() - t_start:.2f}s")
        return True
    else:
        print("Final key solve returned UNSAT!")
        return False

if __name__ == '__main__':
    solve_test14()
