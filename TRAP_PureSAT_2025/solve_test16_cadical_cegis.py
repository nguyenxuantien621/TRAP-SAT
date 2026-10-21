import time
import csv
import sys
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

def main():
    t_start = time.time()
    pl_file = 'test/Test16-TRAP_2x1_C17/trap2x1C17.py'
    io_file = 'test/Test16-TRAP_2x1_C17/trap2x1C17_io.csv'
    key_file = 'test/Test16-TRAP_2x1_C17/extracted_key.csv'

    print("=" * 80, flush=True)
    print("STARTING FULL PURESAT CADICAL153 CEGIS ATTACK (TEST 16: 2x1 C17)", flush=True)
    print("=" * 80, flush=True)

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    ctx = {k: Bool(k) for k in vars_dict}
    ctx.update(exec_ctx_base)

    print("Converting base circuit to CNF via Tseitin...", flush=True)
    t0 = time.time()
    g = Goal()
    for c in clauses_list:
        try: g.add(eval(c, ctx))
        except Exception: pass

    t = Tactic('tseitin-cnf')
    cnf = t(g)[0]
    print(f"CNF generated in {time.time()-t0:.2f}s: {len(cnf)} CNF clauses.", flush=True)

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

    base_cnf_clauses = []
    for cl in cnf:
        if is_or(cl): base_cnf_clauses.append([get_lit_id(arg) for arg in cl.children()])
        else: base_cnf_clauses.append([get_lit_id(cl)])

    key_lit_ids = set([var_map[k] for k in keyVars if k in var_map])
    print(f"Total variables: {len(var_map)}, Shared key variables: {len(key_lit_ids)}", flush=True)

    solver = pysat.solvers.Cadical153()
    N_vars = len(var_map) + 1000

    def add_pattern(p_idx, p1, p2, p3, p6, p7):
        shift = p_idx * N_vars
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

        for cl in base_cnf_clauses:
            shifted_c = []
            for lit in cl:
                vid = abs(lit)
                sign = 1 if lit > 0 else -1
                if vid in key_lit_ids:
                    shifted_c.append(lit)  # Shared key
                else:
                    shifted_c.append(sign * (vid + shift))  # Dynamic per-pattern
            solver.add_clause(shifted_c)

        solver.add_clause([ (var_map['pi1'] + shift) if p1 else -(var_map['pi1'] + shift) ])
        solver.add_clause([ (var_map['pi2'] + shift) if p2 else -(var_map['pi2'] + shift) ])
        solver.add_clause([ (var_map['pi3'] + shift) if p3 else -(var_map['pi3'] + shift) ])
        solver.add_clause([ (var_map['pi6'] + shift) if p6 else -(var_map['pi6'] + shift) ])
        solver.add_clause([ (var_map['pi7'] + shift) if p7 else -(var_map['pi7'] + shift) ])

        solver.add_clause([ (var_map['po22'] + shift) if g22 else -(var_map['po22'] + shift) ])
        solver.add_clause([ (var_map['po23'] + shift) if g23 else -(var_map['po23'] + shift) ])

        solver.add_clause([ (var_map['VL47_1_0'] + shift) ])
        solver.add_clause([ (var_map['VL49_1_0'] + shift) ])

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
    add_pattern(len(constrained_patterns) - 1, *initial_pat)

    print(f"Starting CEGIS loop with initial vector {initial_pat}...\n", flush=True)

    iteration = 0
    while True:
        iteration += 1
        t_iter = time.time()
        print(f"--- Iteration {iteration} (Clauses: {solver.nof_clauses()}, Vars: {solver.nof_vars()}) ---", flush=True)

        res = solver.solve()
        solve_duration = time.time() - t_iter
        print(f"CaDiCaL solve: {res} in {solve_duration:.2f}s", flush=True)

        if not res:
            print("ERROR: CaDiCaL returned UNSAT!", flush=True)
            return False

        model = set(solver.get_model())
        cand_key = {}
        for k in keyVars:
            if k in var_map:
                cand_key[k] = (var_map[k] in model)
            else:
                cand_key[k] = False

        # Fast verification with Cadical assumptions
        t_v = time.time()
        v_solver = pysat.solvers.Cadical153()
        for cl in base_cnf_clauses: v_solver.add_clause(cl)
        for k, val in cand_key.items():
            if k in var_map:
                vid = var_map[k]
                v_solver.add_clause([vid if val else -vid])
        v_solver.add_clause([var_map['VL47_1_0']])
        v_solver.add_clause([var_map['VL49_1_0']])

        pass_count = 0
        counterexample = None

        for vec in all_32_inputs:
            p1, p2, p3, p6, p7 = vec
            g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

            assumptions = [
                var_map['pi1'] if p1 else -var_map['pi1'],
                var_map['pi2'] if p2 else -var_map['pi2'],
                var_map['pi3'] if p3 else -var_map['pi3'],
                var_map['pi6'] if p6 else -var_map['pi6'],
                var_map['pi7'] if p7 else -var_map['pi7'],
            ]
            sat_res = v_solver.solve(assumptions=assumptions)
            if sat_res:
                vm = set(v_solver.get_model())
                f22 = (var_map['po22'] in vm)
                f23 = (var_map['po23'] in vm)
                if (f22 == g22) and (f23 == g23):
                    pass_count += 1
                else:
                    if counterexample is None and vec not in constrained_patterns:
                        counterexample = vec
            else:
                if counterexample is None and vec not in constrained_patterns:
                    counterexample = vec

        v_solver.delete()
        v_duration = time.time() - t_v
        print(f"Verification: {pass_count}/32 passed in {v_duration:.2f}s", flush=True)

        if pass_count == 32:
            print("\n" + "=" * 80, flush=True)
            print("SUCCESS! PERFECT KEY FOUND MATCHING ALL 32/32 VECTORS FOR TEST 16!", flush=True)
            print("=" * 80, flush=True)

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

            print(f"Extracted key saved to {key_file} ({len(clean_rows)} key rows)", flush=True)
            print(f"Total CEGIS Attack Time: {time.time() - t_start:.2f}s", flush=True)
            solver.delete()
            return True

        if counterexample is None:
            for vec in all_32_inputs:
                if vec not in constrained_patterns:
                    counterexample = vec
                    break

        print(f"Adding counterexample vector {counterexample} (Pattern #{len(constrained_patterns)+1})...\n", flush=True)
        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns) - 1, *counterexample)

if __name__ == '__main__':
    main()
