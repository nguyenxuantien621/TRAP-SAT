import time
import csv
import sys
import re
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

def solve_8_patterns():
    t_start = time.time()
    pl_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17.py'
    io_file = 'test/Test14-TRAP_2x2_C17/trap2x2C17_io.csv'
    key_file = 'test/Test14-TRAP_2x2_C17/extracted_key.csv'

    print("=" * 80)
    print("FAST 8-PATTERN SOLVER WITH DATA-WIRE PARTITIONING (TEST 14 C17)")
    print("=" * 80)
    sys.stdout.flush()

    vars_dict, clauses_list = readZ3pl(pl_file)
    inVars, keyVars, outVars, hiZVars = parsePL(io_file)

    def is_data_wire(name):
        if name in inVars or name in outVars:
            return True
        if re.match(r'^L[34]\d_.*$', name):
            return not bool(re.search(r'[A-Za-z]\d.*[A-Za-z]\d', name))
        if re.match(r'^C[1-3]L\d+.*$', name):
            return not bool(re.search(r'C\d.*C\d', name))
        if re.match(r'^C[1-3][NPO]_\d_\d$', name):
            return True
        return False

    data_wires = set([v for v in vars_dict.keys() if is_data_wire(v)])

    static_clauses_code = []
    func_clauses_code = []

    for c in clauses_list:
        tokens = set(re.findall(r'\b[A-Za-z0-9_]+\b', c)).intersection(vars_dict.keys())
        if tokens.intersection(data_wires):
            func_clauses_code.append(compile(c, '<ast>', 'eval'))
        else:
            static_clauses_code.append(compile(c, '<ast>', 'eval'))

    print(f"Clause breakdown: {len(static_clauses_code)} pure static, {len(func_clauses_code)} functional signal")
    sys.stdout.flush()

    exec_ctx_base = {
        'build_magnitude_comparator': build_magnitude_comparator,
        'is_greater_3bit': is_greater_3bit, 'is_greater_4bit': is_greater_4bit,
        'is_greater_5bit': is_greater_5bit, 'is_greater_6bit': is_greater_6bit,
        'is_greater_7bit': is_greater_7bit, 'is_greater_8bit': is_greater_8bit,
        'And': And, 'Or': Or, 'Not': Not, 'Implies': Implies, 'Xor': Xor, 'Bool': Bool
    }

    s = Solver()

    # 1. Base static context
    static_ctx = dict(exec_ctx_base)
    for v in vars_dict.keys():
        static_ctx[v] = Bool(v)

    for code in static_clauses_code:
        s.add(eval(code, static_ctx))

    s.add(static_ctx['VL47_1_1'] == True)
    s.add(static_ctx['VL49_1_1'] == True)

    # 8 diverse test patterns spanning all inputs and outputs
    patterns = [
        (False, False, False, False, False),
        (False, False, False, False, True),
        (False, False, False, True, False),
        (False, False, True, False, False),
        (False, True, False, False, False),
        (True, False, False, False, False),
        (True, True, True, True, True),
        (True, False, True, False, True),
    ]

    for idx, (p1, p2, p3, p6, p7) in enumerate(patterns):
        pat_ctx = dict(static_ctx)
        for v in data_wires:
            pat_ctx[v] = Bool(f'{v}_p{idx}')
        for code in func_clauses_code:
            s.add(eval(code, pat_ctx))
        g22, g23 = compute_golden_c17(p1, p2, p3, p6, p7)
        s.add(pat_ctx['pi1'] == p1)
        s.add(pat_ctx['pi2'] == p2)
        s.add(pat_ctx['pi3'] == p3)
        s.add(pat_ctx['pi6'] == p6)
        s.add(pat_ctx['pi7'] == p7)
        s.add(pat_ctx['po22'] == g22)
        s.add(pat_ctx['po23'] == g23)

    print(f"Solver assertions: {len(s.assertions())}. Solving...")
    sys.stdout.flush()

    t0 = time.time()
    res = s.check()
    print(f"Z3 solve result: {res} in {time.time() - t0:.2f}s!")
    sys.stdout.flush()

    if res != sat:
        print("ERROR: Solver returned UNSAT!")
        return False

    m = s.model()
    clean_rows = []
    with open(io_file, 'r') as f:
        for row in csv.reader(f):
            if row and len(row) > 1 and row[1].strip() == 'key':
                kname = row[0].strip()
                val = is_true(m[static_ctx[kname]]) if kname in static_ctx else False
                clean_rows.append([kname, str(val)])

    with open(key_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(clean_rows)

    print(f"Extracted key saved to {key_file} ({len(clean_rows)} key rows)")
    print(f"Total time: {time.time() - t_start:.2f}s")
    sys.stdout.flush()
    return True

if __name__ == '__main__':
    solve_8_patterns()
