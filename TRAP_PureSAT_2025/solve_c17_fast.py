import csv
import time
import os
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

def solve_c17_pysat():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'

    print("Step 1: Reading PL & IO CSV...")
    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['is_greater_4bit'] = is_greater_4bit
    exec_ctx['is_greater_5bit'] = is_greater_5bit
    exec_ctx['is_greater_6bit'] = is_greater_6bit
    exec_ctx['is_greater_7bit'] = is_greater_7bit
    exec_ctx['is_greater_8bit'] = is_greater_8bit
    exec_ctx.update({'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool})

    print(f"Step 2: Converting Base PL to CNF using Z3 Tseitin ({len(clauses_list)} clauses)...")
    g = Goal()
    for c_str in clauses_list:
        try:
            g.add(eval(c_str, exec_ctx))
        except Exception:
            pass

    t = Tactic('tseitin-cnf')
    cnf = t(g)[0]

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

    all_cnf_clauses = []
    for clause in cnf:
        if is_or(clause):
            c = [get_lit_id(arg) for arg in clause.children()]
        else:
            c = [get_lit_id(clause)]
        all_cnf_clauses.append(c)

    print(f"Total Base CNF variables: {len(var_map)}, Total CNF clauses: {len(all_cnf_clauses)}")

    # Classify variables as static vs dynamic
    # Static: keyVars, DL*, DC*, cnt*, isInp*
    # Dynamic: wires (L*, C*, V*, po*, pi*), and any auxiliary Tseitin variables created for dynamic clauses
    static_names = set(keyVars) | {x for x in var_map.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    
    # Check which Tseitin auxiliary variables are purely static
    # An auxiliary variable is static if all original variables in its connected component are static
    # Or simpler: classify any original named variable not in static_names as dynamic
    dynamic_names = set(var_map.keys()) - static_names

    static_var_ids = {var_map[v] for v in static_names if v in var_map}
    dynamic_var_ids = {var_map[v] for v in dynamic_names if v in var_map}

    print(f"Static original vars: {len(static_var_ids)}, Dynamic vars: {len(dynamic_var_ids)}")

    # Separate static clauses vs dynamic clauses
    # A clause is static if ALL its literals belong to static_var_ids
    static_clauses = []
    dynamic_clauses = []
    for c in all_cnf_clauses:
        if all(abs(lit) in static_var_ids for lit in c):
            static_clauses.append(c)
        else:
            dynamic_clauses.append(c)

    print(f"Static CNF clauses: {len(static_clauses)}, Dynamic CNF clauses: {len(dynamic_clauses)}")

    # Now create PySAT solver (Glucose4 or CaDiCaL)
    solver = pysat.solvers.Glucose4()

    # 1. Add static clauses
    for c in static_clauses:
        solver.add_clause(c)

    # Disable local feedback keys on primary inputs
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
        if fk in var_map:
            solver.add_clause([-var_map[fk]])

    # 2. Add 32 input vectors (exhaustive truth table)
    # Dynamic variable IDs for copy k will be shifted:
    # If lit is dynamic, new_lit = sign(lit) * (abs(lit) + k * num_total_vars)
    N_total = len(var_map) + 1000

    print("Step 3: Instantiating 32 truth table copies into Glucose4...")
    copy_idx = 0
    for p1 in [False, True]:
        for p2 in [False, True]:
            for p3 in [False, True]:
                for p6 in [False, True]:
                    for p7 in [False, True]:
                        copy_idx += 1
                        shift = copy_idx * N_total
                        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

                        # Add shifted dynamic clauses
                        for c in dynamic_clauses:
                            shifted_c = []
                            for lit in c:
                                var = abs(lit)
                                sign = 1 if lit > 0 else -1
                                if var in dynamic_var_ids:
                                    shifted_c.append(sign * (var + shift))
                                else:
                                    # Static var - stays shared!
                                    shifted_c.append(lit)
                            solver.add_clause(shifted_c)

                        # Set inputs for this copy
                        solver.add_clause([ (var_map['pi1'] + shift) if p1 else -(var_map['pi1'] + shift) ])
                        solver.add_clause([ (var_map['pi2'] + shift) if p2 else -(var_map['pi2'] + shift) ])
                        solver.add_clause([ (var_map['pi3'] + shift) if p3 else -(var_map['pi3'] + shift) ])
                        solver.add_clause([ (var_map['pi6'] + shift) if p6 else -(var_map['pi6'] + shift) ])
                        solver.add_clause([ (var_map['pi7'] + shift) if p7 else -(var_map['pi7'] + shift) ])

                        # Set golden outputs for this copy
                        solver.add_clause([ (var_map['po22'] + shift) if g22 else -(var_map['po22'] + shift) ])
                        solver.add_clause([ (var_map['po23'] + shift) if g23 else -(var_map['po23'] + shift) ])

                        # Set validity on outputs
                        if 'VL47_1_1' in var_map:
                            solver.add_clause([ var_map['VL47_1_1'] + shift ])
                        if 'VL49_1_1' in var_map:
                            solver.add_clause([ var_map['VL49_1_1'] + shift ])

    print(f"Step 4: Solving 32-copy CNF with Glucose4 (Clauses: {solver.nof_clauses()}, Vars: {solver.nof_vars()})...")
    t_solve = time.time()
    res = solver.solve()
    print(f"Solver result: {res} in {time.time() - t_solve:.3f}s")

    if not res:
        print("UNSAT! Could not find satisfying key.")
        return False

    model = solver.get_model()
    model_set = set(model)

    key_assignments = {}
    for k in keyVars:
        if k in var_map:
            vid = var_map[k]
            key_assignments[k] = (vid in model_set)
        else:
            key_assignments[k] = False

    # Read the exact 708 rows from trap2x2C17_io.csv to preserve order and duplicates
    extracted_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row:
                kname = row[0].strip()
                val = key_assignments.get(kname, False)
                extracted_rows.append([kname, str(val)])

    out_csv = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(extracted_rows)

    print(f"Successfully wrote {len(extracted_rows)} key assignments to {out_csv}")
    print(f"Total time elapsed: {time.time() - t0:.2f}s")
    solver.delete()
    return True

if __name__ == '__main__':
    solve_c17_pysat()
