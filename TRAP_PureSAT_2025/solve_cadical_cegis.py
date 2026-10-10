import time
import csv
import sys
import re
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

def run_unconstrained_cadical_cegis():
    t0 = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("NATURAL CADICAL CEGIS DEOBFUSCATION (TEST 14 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    static_prefix = ('DL', 'DC', 'cnt', 'isInp', 'VL', 'VC')
    key_set = set(keyVars)
    static_set = key_set | {k for k in vars_dict if any(k.startswith(p) for p in static_prefix)}
    dyn_vars = set(vars_dict.keys()) - static_set

    print(f"Total variables: {len(vars_dict)} (Static: {len(static_set)}, Dynamic: {len(dyn_vars)})")
    sys.stdout.flush()

    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    # Pre-compile AST
    static_clauses_code = []
    dyn_clauses_code = []

    for c in clauses_list:
        tokens = set(re.findall(r'\b[A-Za-z0-9_]+\b', c))
        vars_in_c = tokens.intersection(vars_dict.keys())
        dyn_in_c = vars_in_c.intersection(dyn_vars)
        code = compile(c, '<ast>', 'eval')
        if dyn_in_c:
            dyn_clauses_code.append(code)
        else:
            static_clauses_code.append(code)

    print(f"Clauses: {len(static_clauses_code)} pure static, {len(dyn_clauses_code)} dynamic-dependent")
    sys.stdout.flush()

    t = Tactic('tseitin-cnf')
    var_map = {}
    id_to_var = {}

    def get_lit_id(lit, clause_id):
        neg = is_not(lit)
        v = lit.arg(0) if neg else lit
        vname = str(v)
        if '!' in vname:
            vname = f"aux_{clause_id}_{vname}"
        if vname not in var_map:
            var_id = len(var_map) + 1
            var_map[vname] = var_id
            id_to_var[var_id] = vname
        else:
            var_id = var_map[vname]
        return -var_id if neg else var_id

    static_ctx = dict(exec_ctx_base)
    for v in vars_dict.keys():
        static_ctx[v] = Bool(v)

    print("Converting static clauses to CNF...")
    sys.stdout.flush()
    static_cnf = []
    for idx, code in enumerate(static_clauses_code):
        expr = eval(code, static_ctx)
        g = Goal()
        g.add(expr)
        cnf = t(g)[0]
        for cl in cnf:
            if is_or(cl):
                static_cnf.append([get_lit_id(arg, f"s_{idx}") for arg in cl.children()])
            else:
                static_cnf.append([get_lit_id(cl, f"s_{idx}")])

    print("Converting dynamic clauses to CNF templates...")
    sys.stdout.flush()
    dyn_cnf = []
    for idx, code in enumerate(dyn_clauses_code):
        expr = eval(code, static_ctx)
        g = Goal()
        g.add(expr)
        cnf = t(g)[0]
        for cl in cnf:
            if is_or(cl):
                dyn_cnf.append([get_lit_id(arg, f"d_{idx}") for arg in cl.children()])
            else:
                dyn_cnf.append([get_lit_id(cl, f"d_{idx}")])

    print(f"Base CNF: {len(static_cnf)} static clauses, {len(dyn_cnf)} dynamic clauses, {len(var_map)} variables.")
    sys.stdout.flush()

    static_lit_ids = set()
    for vname, vid in var_map.items():
        if vname in static_set or vname.startswith('aux_s_'):
            static_lit_ids.add(vid)

    # Initialize CaDiCaL Solver
    solver = pysat.solvers.Cadical153()

    # Add static clauses
    for cl in static_cnf:
        solver.add_clause(cl)

    # Enable validities on Tile (1,1) outputs
    if 'VL47_1_1' in var_map:
        solver.add_clause([var_map['VL47_1_1']])
    if 'VL49_1_1' in var_map:
        solver.add_clause([var_map['VL49_1_1']])

    N_vars = len(var_map) + 1000

    def add_pattern_to_cadical(p_idx, p1, p2, p3, p6, p7):
        shift = p_idx * N_vars
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)

        for c in dyn_cnf:
            shifted_c = []
            for lit in c:
                vid = abs(lit)
                sign = 1 if lit > 0 else -1
                if vid in static_lit_ids:
                    shifted_c.append(lit)
                else:
                    shifted_c.append(sign * (vid + shift))
            solver.add_clause(shifted_c)

        solver.add_clause([ (var_map['pi1'] + shift) if p1 else -(var_map['pi1'] + shift) ])
        solver.add_clause([ (var_map['pi2'] + shift) if p2 else -(var_map['pi2'] + shift) ])
        solver.add_clause([ (var_map['pi3'] + shift) if p3 else -(var_map['pi3'] + shift) ])
        solver.add_clause([ (var_map['pi6'] + shift) if p6 else -(var_map['pi6'] + shift) ])
        solver.add_clause([ (var_map['pi7'] + shift) if p7 else -(var_map['pi7'] + shift) ])

        solver.add_clause([ (var_map['po22'] + shift) if g22 else -(var_map['po22'] + shift) ])
        solver.add_clause([ (var_map['po23'] + shift) if g23 else -(var_map['po23'] + shift) ])

    # Pre-build verification Z3 solver
    base_eval_ctx = {k: Bool(k) for k in vars_dict.keys()}
    base_eval_ctx.update(exec_ctx_base)
    base_eval_clauses = []
    for c_str in clauses_list:
        try:
            base_eval_clauses.append(eval(c_str, base_eval_ctx))
        except Exception:
            pass

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
    add_pattern_to_cadical(len(constrained_patterns), *initial_pat)

    print(f"Starting CaDiCaL CEGIS loop with initial vector {initial_pat}...")
    sys.stdout.flush()

    iteration = 0
    while True:
        iteration += 1
        t_iter = time.time()
        print(f"\n--- Iteration {iteration} (Clauses: {solver.nof_clauses()}, Vars: {solver.nof_vars()}) ---")
        sys.stdout.flush()

        res = solver.solve()
        if not res:
            print("CaDiCaL returned UNSAT!")
            return False

        model = set(solver.get_model())
        cand_key = {}
        for k in keyVars:
            if k in var_map:
                cand_key[k] = (var_map[k] in model)
            else:
                cand_key[k] = False

        print(f"CaDiCaL solved in {time.time() - t_iter:.2f}s. Verifying against 32 vectors...")
        sys.stdout.flush()

        v_solver = Solver()
        for c in base_eval_clauses:
            v_solver.add(c)
        for k, val in cand_key.items():
            if k in base_eval_ctx:
                v_solver.add(base_eval_ctx[k] == val)
        v_solver.add(base_eval_ctx['VL47_1_1'] == True)
        v_solver.add(base_eval_ctx['VL49_1_1'] == True)

        counterexample = None
        pass_count = 0

        for vec in all_32_inputs:
            p1, p2, p3, p6, p7 = vec
            g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
            v_solver.push()
            v_solver.add(base_eval_ctx['pi1'] == p1)
            v_solver.add(base_eval_ctx['pi2'] == p2)
            v_solver.add(base_eval_ctx['pi3'] == p3)
            v_solver.add(base_eval_ctx['pi6'] == p6)
            v_solver.add(base_eval_ctx['pi7'] == p7)

            if v_solver.check() == sat:
                vm = v_solver.model()
                f22 = is_true(vm[base_eval_ctx['po22']])
                f23 = is_true(vm[base_eval_ctx['po23']])
                if (f22 == g22) and (f23 == g23):
                    pass_count += 1
                else:
                    if counterexample is None and vec not in constrained_patterns:
                        counterexample = vec
            else:
                if counterexample is None and vec not in constrained_patterns:
                    counterexample = vec
            v_solver.pop()

        print(f"Candidate passed {pass_count}/32 vectors!")
        sys.stdout.flush()

        if pass_count == 32:
            print("\n" + "=" * 80)
            print("SUCCESS! PERFECT KEY FOUND MATCHING ALL 32/32 VECTORS!")
            print("=" * 80)
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

            print(f"Saved {len(clean_rows)} keys to {key_file} in {time.time() - t0:.2f}s total.")
            solver.delete()
            return True

        if counterexample is None:
            for vec in all_32_inputs:
                if vec not in constrained_patterns:
                    counterexample = vec
                    break

        print(f"Adding counterexample vector {counterexample} as new constraint...")
        sys.stdout.flush()
        constrained_patterns.add(counterexample)
        add_pattern_to_cadical(len(constrained_patterns), *counterexample)

if __name__ == '__main__':
    run_unconstrained_cadical_cegis()
