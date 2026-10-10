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

def run_in_memory_attack():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'

    print("=" * 80)
    print("STARTING IN-MEMORY Z3 SAT ATTACK FOR TEST 14 (TRAP 2x2 C17)")
    print("=" * 80)

    # 1. Read PL & IO CSV
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

    print(f"Parsing {len(clauses_list)} clauses into Z3 AST...")
    base_clauses_ast = []
    for c_str in clauses_list:
        try:
            base_clauses_ast.append(eval(c_str, exec_ctx))
        except Exception:
            pass

    # Classify static vs dynamic variables
    static_names = set(keyVars) | {x for x in vars_dict.keys() if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    dynamic_names = set(vars_dict.keys()) - static_names

    print(f"Static variables: {len(static_names)}, Dynamic variables: {len(dynamic_names)}")

    # Pre-split clauses into static and dynamic
    static_clauses_ast = []
    dynamic_clauses_ast = []
    for ast in base_clauses_ast:
        # Check if contains dynamic variables
        used_vars = {str(v) for v in ast.children()} # Quick approximate check or ast traverse
        # More robust: check if any dynamic symbol is in the AST
        is_dyn = any(d in str(ast) for d in ['L3', 'L4', 'C1', 'C2', 'C3', 'pi', 'po', 'V'])
        if is_dyn and ('is_greater_' not in str(ast)):
            dynamic_clauses_ast.append(ast)
        else:
            static_clauses_ast.append(ast)

    print(f"Static clauses: {len(static_clauses_ast)}, Dynamic clauses: {len(dynamic_clauses_ast)}")

    # Function to instantiate dynamic clauses for a specific suffix and specific key set
    # key_map: dict mapping static key/DL/cnt vars to key_1 or key_2 (for Miter)
    def instantiate_circuit(suffix, key_suffix=''):
        sub_list = []
        # Dynamic vars substitution
        for d in dynamic_names:
            sub_list.append((exec_ctx[d], Bool(f"{d}{suffix}")))
        # If key_suffix is specified, substitute static vars too (for Miter copy 1 & 2)
        if key_suffix:
            for s in static_names:
                sub_list.append((exec_ctx[s], Bool(f"{s}{key_suffix}")))
        
        inst_clauses = [substitute(c, sub_list) for c in dynamic_clauses_ast]
        return inst_clauses

    def instantiate_static(key_suffix):
        sub_list = [(exec_ctx[s], Bool(f"{s}{key_suffix}")) for s in static_names]
        return [substitute(c, sub_list) for c in static_clauses_ast]

    # Feedback key suppression
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

    # 2. Build Miter Solver
    print("Building Miter solver...")
    miter_solver = Solver()

    # Static constraints for K1 and K2
    miter_solver.add(instantiate_static('_1'))
    miter_solver.add(instantiate_static('_2'))

    for fk in feedback_keys:
        if fk in exec_ctx:
            miter_solver.add(Bool(f"{fk}_1") == False)
            miter_solver.add(Bool(f"{fk}_2") == False)

    # Dynamic copy 1 and copy 2 for Miter difference search
    miter_solver.add(instantiate_circuit('_m1', key_suffix='_1'))
    miter_solver.add(instantiate_circuit('_m2', key_suffix='_2'))

    # Tie primary inputs of m1 and m2 together to common input variables (pi1..pi7)
    for inv in inVars:
        miter_solver.add(Bool(f"{inv}_m1") == Bool(inv))
        miter_solver.add(Bool(f"{inv}_m2") == Bool(inv))

    # Enable output validity for m1 and m2
    miter_solver.add(Bool('VL47_1_1_m1') == True)
    miter_solver.add(Bool('VL49_1_1_m1') == True)
    miter_solver.add(Bool('VL47_1_1_m2') == True)
    miter_solver.add(Bool('VL49_1_1_m2') == True)

    # Miter difference condition: outputs differ
    diff_clauses = [
        Xor(Bool(f"{outv}_m1"), Bool(f"{outv}_m2")) for outv in outVars
    ]
    miter_solver.add(Or(*diff_clauses))

    # 3. Iterative DIP Loop
    all_dips = []
    round_num = 1
    max_rounds = 35

    while round_num <= max_rounds:
        t_r = time.time()
        print(f"Round #{round_num}: Solving Miter for DIP...")
        res = miter_solver.check()
        if res != sat:
            print(f"Miter returned {res}! Attack loop terminated at round #{round_num}.")
            break

        model = miter_solver.model()
        dip = {}
        for inv in inVars:
            dip[inv] = is_true(model[Bool(inv)])

        print(f"  -> Extracted DIP #{round_num}: {dip} (in {time.time() - t_r:.2f}s)")
        all_dips.append(dip)

        # Query Oracle (compute golden C17 output)
        g22, g23 = compute_golden_c17(dip['pi1'], dip['pi2'], dip['pi3'], dip['pi6'], dip['pi7'])
        oracle_out = {'po22': g22, 'po23': g23}
        print(f"  -> Oracle Output: {oracle_out}")

        # Add DIP constraints to both K1 and K2 in Miter Solver
        # Circuit for DIP on K1
        miter_solver.add(instantiate_circuit(f'_cp{round_num}_1', key_suffix='_1'))
        for inv in inVars:
            miter_solver.add(Bool(f"{inv}_cp{round_num}_1") == dip[inv])
        for outv, oval in oracle_out.items():
            miter_solver.add(Bool(f"{outv}_cp{round_num}_1") == oval)
        miter_solver.add(Bool(f"VL47_1_1_cp{round_num}_1") == True)
        miter_solver.add(Bool(f"VL49_1_1_cp{round_num}_1") == True)

        # Circuit for DIP on K2
        miter_solver.add(instantiate_circuit(f'_cp{round_num}_2', key_suffix='_2'))
        for inv in inVars:
            miter_solver.add(Bool(f"{inv}_cp{round_num}_2") == dip[inv])
        for outv, oval in oracle_out.items():
            miter_solver.add(Bool(f"{outv}_cp{round_num}_2") == oval)
        miter_solver.add(Bool(f"VL47_1_1_cp{round_num}_2") == True)
        miter_solver.add(Bool(f"VL49_1_1_cp{round_num}_2") == True)

        # Input blocking clause to prevent re-extracting the same DIP
        block_terms = [Bool(inv) != val for inv, val in dip.items()]
        miter_solver.add(Or(*block_terms))

        round_num += 1

    # 4. Final Key Solve
    print("\nSolving Final Key on all accumulated DIP constraints...")
    final_solver = Solver()
    final_solver.add(static_clauses_ast)
    for fk in feedback_keys:
        if fk in exec_ctx:
            final_solver.add(exec_ctx[fk] == False)

    for i, dip in enumerate(all_dips, 1):
        final_solver.add(instantiate_circuit(f'_final_cp{i}'))
        for inv in inVars:
            final_solver.add(Bool(f"{inv}_final_cp{i}") == dip[inv])
        g22, g23 = compute_golden_c17(dip['pi1'], dip['pi2'], dip['pi3'], dip['pi6'], dip['pi7'])
        final_solver.add(Bool(f"po22_final_cp{i}") == g22)
        final_solver.add(Bool(f"po23_final_cp{i}") == g23)
        final_solver.add(Bool(f"VL47_1_1_final_cp{i}") == True)
        final_solver.add(Bool(f"VL49_1_1_final_cp{i}") == True)

    if final_solver.check() == sat:
        final_model = final_solver.model()
        print("FINAL KEY SOLVE: SAT!")
        
        extracted_rows = []
        with open(io_file, 'r') as f:
            for row in csv.reader(f):
                if row:
                    kname = row[0].strip()
                    val = is_true(final_model[exec_ctx[kname]]) if kname in exec_ctx else False
                    extracted_rows.append([kname, str(val)])

        out_csv = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'
        with open(out_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(extracted_rows)

        print(f"Extracted key written to: {out_csv} ({len(extracted_rows)} rows)")
        print(f"Total attack time: {time.time() - t_start:.2f}s")
        return True
    else:
        print("ERROR: Final solve UNSAT!")
        return False

if __name__ == '__main__':
    run_in_memory_attack()
