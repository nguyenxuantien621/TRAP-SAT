import sys
import os
import csv
from z3 import *

sys.path.insert(0, r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025')
from src.satAttack import readZ3pl

def test_solve_with_validity():
    dip_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\work\dipCircuits.py'
    io_csv = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\test\Test13-TRAP_2x2_AOI22\trap2x2AOI22_io.csv'

    keyVars = []
    hiZVars = {}
    with open(io_csv) as f:
        for row in csv.reader(f):
            if not row:
                continue
            if row[1] == 'key':
                keyVars.append(row[0])
            elif row[1] == 'output' and len(row) > 2:
                hiZVars[row[0]] = row[2]

    vars_dict, clauses_list = readZ3pl(dip_file)
    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['is_greater_3bit'] = lambda B2, B1, B0, A2, A1, A0: Or(And(B2, Not(A2)), And(B2 == A2, B1, Not(A1)), And(B2 == A2, B1 == A1, B0, Not(A0)))
    exec_ctx['And'] = And
    exec_ctx['Or'] = Or
    exec_ctx['Not'] = Not
    exec_ctx['Implies'] = Implies
    exec_ctx['Xor'] = Xor
    exec_ctx['Bool'] = Bool

    s = Solver()
    for c_str in clauses_list:
        try:
            s.add(eval(c_str, exec_ctx))
        except Exception:
            pass

    # Add validity constraint for all 16 copies
    for rnd in range(1, 17):
        for hz in hiZVars.values():
            vname = f'{hz}_cp{rnd}'
            if vname in exec_ctx:
                s.add(exec_ctx[vname] == True)

    print("Checking SAT with validity constraints...")
    if s.check() == sat:
        print("SAT! Key found with ACTIVE DRIVE (VL47_0_0 == True)!")
        m = s.model()
        new_key = {k: is_true(m[exec_ctx[k]]) if k in exec_ctx and m[exec_ctx[k]] is not None else False for k in set(keyVars)}
        
        # Save key
        key_out = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\work\extracted_key.csv'
        with open(key_out, 'w', newline='') as f:
            writer = csv.writer(f)
            for k, v in new_key.items():
                writer.writerow([k, v])
        
        # Test this new key against truth table
        pl_file = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_PureSAT_2025\test\Test13-TRAP_2x2_AOI22\trap2x2AOI22.py'
        pvars, pclauses = readZ3pl(pl_file)
        pctx = {k: Bool(k) for k in pvars.keys()}
        pctx['is_greater_3bit'] = lambda B2, B1, B0, A2, A1, A0: Or(And(B2, Not(A2)), And(B2 == A2, B1, Not(A1)), And(B2 == A2, B1 == A1, B0, Not(A0)))
        pctx['And'] = And
        pctx['Or'] = Or
        pctx['Not'] = Not
        pctx['Implies'] = Implies
        pctx['Xor'] = Xor
        pctx['Bool'] = Bool
        
        pbase = []
        for cs in pclauses:
            try:
                pbase.append(eval(cs, pctx))
            except Exception:
                pass
            
        all_pass = True
        print("\nTesting Full Truth Table (16 patterns):")
        for a_val in [False, True]:
            for b_val in [False, True]:
                for c_val in [False, True]:
                    for d_val in [False, True]:
                        golden = not ((a_val and b_val) or (c_val and d_val))
                        st = Solver()
                        for cb in pbase:
                            st.add(cb)
                        st.add(pctx['a'] == a_val, pctx['b'] == b_val, pctx['c'] == c_val, pctx['d'] == d_val)
                        for k, v in new_key.items():
                            if k in pctx:
                                st.add(pctx[k] == v)
                        if st.check() == sat:
                            mo = st.model()
                            fo = is_true(mo[pctx['o']])
                            match = (fo == golden)
                            if not match:
                                all_pass = False
                            print(f"Inputs ({int(a_val)},{int(b_val)},{int(c_val)},{int(d_val)}) | Golden: {int(golden)} | Fabric: {int(fo)} | {'PASS' if match else 'FAIL'}")
                        else:
                            print("UNSAT on input pattern!")
                            all_pass = False
        print(f"\nALL 16 PATTERNS MATCH 100%: {all_pass}")
    else:
        print("UNSAT!")

if __name__ == '__main__':
    test_solve_with_validity()
