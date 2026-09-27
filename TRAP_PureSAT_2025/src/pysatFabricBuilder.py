#!/usr/bin/env python3
'''
Script for writing Pure Boolean (CNF-compatible) Propositional Logic clauses of the TRAP circuit architecture.
Dynamically scales the 'cnt' loop-prevention variables to arbitrary N-bit Boolean vectors (b0, b1, ..., b(N-1))
and generates exact Pure Boolean Magnitude Comparators (Bit-Blasting).

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import re
import csv
import importlib
import argparse
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

def generate_comparator_code(n_bits: int) -> str:
    '''
    Generates pure Boolean N-bit Magnitude Comparator function code: B > A
    Using MSB-to-LSB Bit-blasting Digital Comparator Algorithm.
    '''
    args_B = ", ".join([f"B{i}" for i in reversed(range(n_bits))])
    args_A = ", ".join([f"A{i}" for i in reversed(range(n_bits))])
    
    terms = []
    for i in range(n_bits - 1, -1, -1):
        eq_conditions = [f"B{j} == A{j}" for j in range(n_bits - 1, i, -1)]
        current_cond = f"B{i}, Not(A{i})"
        if eq_conditions:
            terms.append(f"And({', '.join(eq_conditions)}, {current_cond})")
        else:
            terms.append(f"And({current_cond})")
            
    code = f"def is_greater_{n_bits}bit({args_B}, {args_A}):\n"
    for idx, term in enumerate(terms):
        code += f"\tt{idx+1} = {term}\n"
    code += f"\treturn Or({', '.join([f't{k+1}' for k in range(len(terms))])})\n\n"
    return code

def pysatFabricBuilder(numCols: int, numRows: int, pinMapCSV: str, outModelFn='trapModel', n_bits=None):
    '''
    Generates a Pure Boolean model file replacing all Int variables with N-bit Boolean vectors.
    Auto-scales n_bits if not specified:
      - 1 Tile (1x1): 4 bits (0..15)
      - 2 to 4 Tiles (2x1, 2x2): 5 bits (0..31)
      - > 4 Tiles (3x3, 4x4): 6 bits (0..63)
    '''
    total_tiles = numCols * numRows
    if n_bits is None:
        if total_tiles <= 1:
            n_bits = 4
        elif total_tiles <= 4:
            n_bits = 5
        else:
            n_bits = 6

    print(f"[*] Building Pure Boolean TRAP Fabric: {numCols}x{numRows} ({total_tiles} tiles) with {n_bits}-bit cnt scaling (max depth {2**n_bits - 1})...")

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
    
    # Replace Int declarations with N-bit Bool declarations
    for iv in int_vars:
        bit_decls = "\n\t".join([f"{iv}_b{k} = Bool('{iv}_b{k}')" for k in range(n_bits)])
        content = content.replace(f"{iv} = Int('{iv}')", bit_decls)

    # Replace integer comparisons (cntB > cntA) with is_greater_Nbit
    func_name = f"is_greater_{n_bits}bit"
    def repl_comp(match):
        vB = match.group(1)
        vA = match.group(2)
        b_args = ", ".join([f"{vB}_b{k}" for k in reversed(range(n_bits))])
        a_args = ", ".join([f"{vA}_b{k}" for k in reversed(range(n_bits))])
        return f"{func_name}({b_args}, {a_args})"

    content = re.sub(r'\b(cnt[A-Za-z0-9_]+|minCnt|maxCnt)\s*>\s*(cnt[A-Za-z0-9_]+|minCnt|maxCnt)\b', repl_comp, content)
    content = content.replace("minCnt == -1", "minCnt_b0 == False")
    content = content.replace("maxCnt == 10", "maxCnt_b0 == True")

    # Prepend the generated dynamic comparator function
    comparator_code = generate_comparator_code(n_bits)
    header = f"from z3 import *\n\n{comparator_code}"
    
    if func_name not in content:
        content = content.replace("from z3 import *\n", header)

    final_fn = outModelFn + '.py'
    with open(final_fn, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[+] Pure Boolean fabric model {final_fn} generated successfully with {n_bits}-bit cnt (zero Int theories)!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build Pure Boolean TRAP Fabric Model with N-bit cnt scaling')
    parser.add_argument('numCols', type=int, help='Number of columns')
    parser.add_argument('numRows', type=int, help='Number of rows')
    parser.add_argument('pinMap', type=str, help='Path to pinMap CSV')
    parser.add_argument('-o', '--output', dest='outModel', default='trapModel', help='Output model name')
    parser.add_argument('-b', '--bits', dest='bits', type=int, default=None, help='Number of bits for cnt (default: auto-scale)')
    args = parser.parse_args()

    pysatFabricBuilder(args.numCols, args.numRows, args.pinMap, outModelFn=args.outModel, n_bits=args.bits)
