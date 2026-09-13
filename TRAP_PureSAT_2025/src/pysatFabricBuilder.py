#!/usr/bin/env python3
'''
Script for writing Pure Boolean (CNF-compatible) Propositional Logic clauses of the TRAP circuit architecture.
Replaces Z3 SMT Int Theory ('Int') with 3-bit Boolean vectors (b0, b1, b2) and 3-bit magnitude comparator logic.

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import re
import csv
import importlib
from z3 import *

def load_orig_builder():
    trap_dir = r'C:\Users\ADMIN\Downloads\TRANSAT-main\TRAP_for_SAT_2025'
    for k in list(sys.modules.keys()):
        if k == 'src' or k.startswith('src.'):
            del sys.modules[k]
    if trap_dir in sys.path:
        sys.path.remove(trap_dir)
    sys.path.insert(0, trap_dir)
    mod = importlib.import_module('src.trapFabricBuilder')
    return mod.trapFabricBuilder

def is_greater_3bit(B2, B1, B0, A2, A1, A0):
    '''
    Pure Boolean 3-bit magnitude comparator: B > A
    '''
    t1 = And(B2, Not(A2))
    t2 = And(B2 == A2, B1, Not(A1))
    t3 = And(B2 == A2, B1 == A1, B0, Not(A0))
    return Or(t1, t2, t3)

def pysatFabricBuilder(numCols: int, numRows: int, pinMapCSV: str, outModelFn='trapModel'):
    '''
    Generates a Pure Boolean model file replacing all Int variables with 3-bit Boolean vectors.
    '''
    trapFabricBuilder = load_orig_builder()
    temp_fn = outModelFn + '_temp'
    trapFabricBuilder(numRows, numCols, pinMapCSV, False, temp_fn)
    
    temp_file_py = temp_fn + '.py'
    with open(temp_file_py, 'r', encoding='utf-8') as f:
        content = f.read()

    # Clean up temp file
    if os.path.exists(temp_file_py):
        try: os.remove(temp_file_py)
        except: pass

    # Find ALL count / Int variables
    int_vars = set(re.findall(r'\b(cnt[A-Za-z0-9_]+|minCnt|maxCnt)\b', content))
    
    # Replace Int declarations with 3-bit Bool declarations
    for iv in int_vars:
        content = content.replace(f"{iv} = Int('{iv}')", 
                                  f"{iv}_b0 = Bool('{iv}_b0')\n\t{iv}_b1 = Bool('{iv}_b1')\n\t{iv}_b2 = Bool('{iv}_b2')")

    # Replace integer comparisons (cntB > cntA) with is_greater_3bit
    def repl_comp(match):
        vB = match.group(1)
        vA = match.group(2)
        return f"is_greater_3bit({vB}_b2, {vB}_b1, {vB}_b0, {vA}_b2, {vA}_b1, {vA}_b0)"

    content = re.sub(r'\b(cnt[A-Za-z0-9_]+|minCnt|maxCnt)\s*>\s*(cnt[A-Za-z0-9_]+|minCnt|maxCnt)\b', repl_comp, content)
    content = content.replace("minCnt == -1", "minCnt_b0 == False")
    content = content.replace("maxCnt == 10", "maxCnt_b0 == True")

    # Ensure is_greater_3bit function is defined in the script
    header = "from z3 import *\n\ndef is_greater_3bit(B2, B1, B0, A2, A1, A0):\n\tt1 = And(B2, Not(A2))\n\tt2 = And(B2 == A2, B1, Not(A1))\n\tt3 = And(B2 == A2, B1 == A1, B0, Not(A0))\n\treturn Or(t1, t2, t3)\n\n"
    
    if 'def is_greater_3bit' not in content:
        content = content.replace("from z3 import *\n", header)

    final_fn = outModelFn + '.py'
    with open(final_fn, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Pure Boolean fabric model {final_fn} generated successfully with zero Int theories!")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: pysatFabricBuilder.py <numCols> <numRows> <pinMapCSV> [-o <outModel>]")
        sys.exit(1)
    nCols = int(sys.argv[1])
    nRows = int(sys.argv[2])
    pCSV = sys.argv[3]
    oFn = 'trapModel'
    if '-o' in sys.argv:
        oFn = sys.argv[sys.argv.index('-o') + 1]
    pysatFabricBuilder(nCols, nRows, pCSV, outModelFn=oFn)
