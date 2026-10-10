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

def run_fast_attack():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("FAST ITERATIVE SAT ATTACK (TEST 14 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)
    key_set = set(keyVars)
    in_set = set(inVars)
    out_set = set(outVars)

    print(f"Loaded PL: {len(vars_dict)} variables, {len(clauses_list)} clauses")
    print(f"Inputs: {inVars}, Outputs: {outVars}, Keys: {len(key_set)}")
    sys.stdout.flush()

    # Pre-parse clauses into AST
    exec_ctx_base = {'build_magnitude_comparator': build_magnitude_comparator,
                     'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
                     'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
                     'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
                     'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool}

    compiled_clauses = []
    for c_str in clauses_list:
        try:
            code = compile(c_str, '<ast>', 'eval')
            compiled_clauses.append(code)
        except Exception as e:
            pass

    print(f"Compiled {len(compiled_clauses)} clause ASTs in {time.time() - t0:.2f}s")
    sys.stdout.flush()

    # Helper to instantiate circuit copy
    def instantiate_circuit(prefix):
        ctx = dict(exec_ctx_base)
        for v in vars_dict.keys():
            if v in key_set:
                ctx[v] = Bool(v) # shared key
            elif v in in_set:
                ctx[v] = Bool(f"{v}_{prefix}")
            else:
                ctx[v] = Bool(f"{v}_{prefix}")
        
        clauses = []
        for code in compiled_clauses:
            clauses.append(eval(code, ctx))
        return ctx, clauses

    # Create Miter Solver
    solver = Solver()
    
    # Suppress primary input feedback keys to avoid spurious cycles
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
        if fk in vars_dict:
            solver.add(Not(Bool(fk)))

    # Iterative DIP Attack Loop
    # Key instances: K1, K2 for miter
    # In each iteration i:
    #   Create circuit 1 with (X, K1, Y1_i)
    #   Create circuit 2 with (X, K2, Y2_i)
    #   Assert Y1_i != Y2_i (miter output difference)
    #   Solve for DIP X
    #   If UNSAT -> converged!
    #   If SAT -> get DIP X_val, query oracle Y_val = Golden(X_val)
    #   Add persistent constraints: circuit(X_val, K1, Y_val), circuit(X_val, K2, Y_val)
    #   Remove miter difference for next round.

    print("Starting DIP search loop...")
    sys.stdout.flush()

    # We maintain persistent IO constraints for key variables
    # Let K be the shared key variables
    # We can use a simpler and highly efficient Incremental IO Matching:
    # Instead of full miter duplication (which creates 2x copies per iteration),
    # we can do iterative counterexample search or batch subset!
    # Let's test solving with a small set of distinguishing vectors:
    # Since C17 has only 32 vectors, let's see how fast Z3 solves 1, 2, 4, 8 vectors.

    # Let's instantiate 4 representative vectors first:
    test_vectors = [
        (False, False, False, False, False),
        (True, True, True, True, True),
        (True, False, True, False, True),
        (False, True, False, True, False),
        (True, True, False, False, True),
        (False, False, True, True, False),
        (True, False, False, True, False),
        (False, True, True, False, True),
    ]

    s = Solver()
    for fk in feedback_keys:
        if fk in vars_dict:
            s.add(Not(Bool(fk)))

    print(f"Adding {len(test_vectors)} test patterns to Z3 Solver...")
    for idx, (p1, p2, p3, p6, p7) in enumerate(test_vectors):
        prefix = f"p{idx}"
        ctx, cls = instantiate_circuit(prefix)
        for c in cls:
            s.add(c)
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
        s.add(ctx['pi1'] == p1)
        s.add(ctx['pi2'] == p2)
        s.add(ctx['pi3'] == p3)
        s.add(ctx['pi6'] == p6)
        s.add(ctx['pi7'] == p7)
        s.add(ctx['po22'] == g22)
        s.add(ctx['po23'] == g23)
        if 'VL47_1_1' in ctx:
            s.add(ctx['VL47_1_1'] == True)
        if 'VL49_1_1' in ctx:
            s.add(ctx['VL49_1_1'] == True)

    print(f"Solver has {len(s.assertions())} assertions. Checking satisfiability...")
    sys.stdout.flush()
    t_solve = time.time()
    res = s.check()
    print(f"Z3 Solve result: {res} in {time.time() - t_solve:.2f}s!")
    sys.stdout.flush()

    if res == sat:
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
        print(f"Saved candidate key with {len(clean_rows)} keys.")

if __name__ == '__main__':
    run_fast_attack()
