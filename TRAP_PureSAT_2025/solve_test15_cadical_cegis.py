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

def compute_golden_aoi22(a, b, c, d):
    return not ((a and b) or (c and d))

def main():
    t_start = time.time()
    pl_file = 'test/Test15-TRAP_2x1_AOI22/trap2x1AOI22.py'
    io_file = 'test/Test15-TRAP_2x1_AOI22/trap2x1AOI22_io.csv'
    key_file = 'test/Test15-TRAP_2x1_AOI22/extracted_key.csv'

    print("=" * 80, flush=True)
    print("STARTING FULL PURESAT CADICAL153 CEGIS ATTACK (TEST 15: 2x1 AOI22)", flush=True)
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

    def add_pattern(p_idx, a_val, b_val, c_val, d_val):
        shift = p_idx * N_vars
        golden_o = compute_golden_aoi22(a_val, b_val, c_val, d_val)

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

        solver.add_clause([ (var_map['a'] + shift) if a_val else -(var_map['a'] + shift) ])
        solver.add_clause([ (var_map['b'] + shift) if b_val else -(var_map['b'] + shift) ])
        solver.add_clause([ (var_map['c'] + shift) if c_val else -(var_map['c'] + shift) ])
        solver.add_clause([ (var_map['d'] + shift) if d_val else -(var_map['d'] + shift) ])

        solver.add_clause([ (var_map['o'] + shift) if golden_o else -(var_map['o'] + shift) ])
        solver.add_clause([ (var_map['VL47_0_0'] + shift) ])

    all_16_inputs = []
    for a_val in [False, True]:
        for b_val in [False, True]:
            for c_val in [False, True]:
                for d_val in [False, True]:
                    all_16_inputs.append((a_val, b_val, c_val, d_val))

    constrained_patterns = set()
    initial_pat = (False, False, False, False)
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
        v_solver.add_clause([var_map['VL47_0_0']])

        pass_count = 0
        counterexample = None

        for vec in all_16_inputs:
            a_val, b_val, c_val, d_val = vec
            golden_o = compute_golden_aoi22(a_val, b_val, c_val, d_val)

            assumptions = [
                var_map['a'] if a_val else -var_map['a'],
                var_map['b'] if b_val else -var_map['b'],
                var_map['c'] if c_val else -var_map['c'],
                var_map['d'] if d_val else -var_map['d'],
            ]
            sat_res = v_solver.solve(assumptions=assumptions)
            if sat_res:
                vm = set(v_solver.get_model())
                fo = (var_map['o'] in vm)
                if fo == golden_o:
                    pass_count += 1
                else:
                    if counterexample is None and vec not in constrained_patterns:
                        counterexample = vec
            else:
                if counterexample is None and vec not in constrained_patterns:
                    counterexample = vec

        v_solver.delete()
        v_duration = time.time() - t_v
        print(f"Verification: {pass_count}/16 passed in {v_duration:.2f}s", flush=True)

        if pass_count == 16:
            print("\n" + "=" * 80, flush=True)
            print("SUCCESS! PERFECT KEY FOUND MATCHING ALL 16/16 VECTORS FOR TEST 15!", flush=True)
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
            for vec in all_16_inputs:
                if vec not in constrained_patterns:
                    counterexample = vec
                    break

        print(f"Adding counterexample vector {counterexample} (Pattern #{len(constrained_patterns)+1})...\n", flush=True)
        constrained_patterns.add(counterexample)
        add_pattern(len(constrained_patterns) - 1, *counterexample)

if __name__ == '__main__':
    main()
