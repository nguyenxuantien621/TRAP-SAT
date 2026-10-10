import time
import csv
import sys
from z3 import *
import pysat.solvers
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

def solve_pysat_32():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("PURESAT (GLUCOSE4) 32-VECTOR PARALLEL SOLVER (TEST 14 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)
    key_set = set(keyVars)

    print(f"Total variables: {len(vars_dict)} (Keys: {len(key_set)})")
    print(f"Total clauses: {len(clauses_list)}")
    sys.stdout.flush()

    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['is_greater_4bit'] = is_greater_4bit
    exec_ctx['is_greater_5bit'] = is_greater_5bit
    exec_ctx['is_greater_6bit'] = is_greater_6bit
    exec_ctx['is_greater_7bit'] = is_greater_7bit
    exec_ctx['is_greater_8bit'] = is_greater_8bit
    exec_ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})

    # Convert base PL to Tseitin CNF per clause
    t = Tactic('tseitin-cnf')
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

    print("Converting base PL clauses to CNF...")
    sys.stdout.flush()
    base_cnf_clauses = []
    for idx, c_str in enumerate(clauses_list):
        try:
            expr = eval(c_str, exec_ctx)
            g = Goal()
            g.add(expr)
            cnf = t(g)[0]
            for cl in cnf:
                if is_or(cl):
                    c = [get_lit_id(arg) for arg in cl.children()]
                else:
                    c = [get_lit_id(cl)]
                base_cnf_clauses.append(c)
        except Exception as e:
            pass

    print(f"Base CNF generated in {time.time() - t0:.2f}s: {len(var_map)} variables, {len(base_cnf_clauses)} clauses")
    sys.stdout.flush()

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

    key_var_ids = {var_map[k] for k in key_set if k in var_map}
    N_vars = len(var_map) + 1000

    print("Initializing Glucose4 solver with 32 shifted pattern instances...")
    sys.stdout.flush()
    solver = pysat.solvers.Glucose4()

    # Suppress primary input feedback keys
    for fk in feedback_keys:
        if fk in var_map:
            solver.add_clause([-var_map[fk]])

    pattern_idx = 0
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        pattern_idx += 1
                        shift = pattern_idx * N_vars
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

                        # Shift non-key variables
                        for c in base_cnf_clauses:
                            shifted_c = []
                            for lit in c:
                                vid = abs(lit)
                                sign = 1 if lit > 0 else -1
                                if vid in key_var_ids:
                                    shifted_c.append(lit) # Shared key!
                                else:
                                    shifted_c.append(sign * (vid + shift)) # Pattern-specific
                            solver.add_clause(shifted_c)

                        # Fix inputs for this pattern
                        solver.add_clause([ (var_map['pi1'] + shift) if p1 else -(var_map['pi1'] + shift) ])
                        solver.add_clause([ (var_map['pi2'] + shift) if p2 else -(var_map['pi2'] + shift) ])
                        solver.add_clause([ (var_map['pi3'] + shift) if p3 else -(var_map['pi3'] + shift) ])
                        solver.add_clause([ (var_map['pi6'] + shift) if p6 else -(var_map['pi6'] + shift) ])
                        solver.add_clause([ (var_map['pi7'] + shift) if p7 else -(var_map['pi7'] + shift) ])

                        # Fix outputs for this pattern
                        solver.add_clause([ (var_map['po22'] + shift) if g22 else -(var_map['po22'] + shift) ])
                        solver.add_clause([ (var_map['po23'] + shift) if g23 else -(var_map['po23'] + shift) ])

                        # Fix validities
                        if 'VL47_1_1' in var_map:
                            solver.add_clause([ var_map['VL47_1_1'] + shift ])
                        if 'VL49_1_1' in var_map:
                            solver.add_clause([ var_map['VL49_1_1'] + shift ])

    print(f"Total clauses in Glucose4: {solver.nof_clauses()}, Total variables: {solver.nof_vars()}")
    print("Solving with Glucose4 CDCL engine...")
    sys.stdout.flush()

    t_solve = time.time()
    res = solver.solve()
    print(f"Glucose4 solve result: {res} in {time.time() - t_solve:.2f}s!")
    sys.stdout.flush()

    if not res:
        print("ERROR: Glucose4 returned UNSAT!")
        return False

    model = set(solver.get_model())

    clean_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row and len(row) > 1 and row[1].strip() == 'key':
                kname = row[0].strip()
                if kname in var_map:
                    val = (var_map[kname] in model)
                else:
                    val = False
                clean_rows.append([kname, str(val)])

    with open(key_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(clean_rows)

    print(f"Successfully extracted {len(clean_rows)} keys to {key_file} in {time.time() - t0:.2f}s!")
    sys.stdout.flush()
    solver.delete()
    return True

if __name__ == '__main__':
    solve_pysat_32()
