#!/usr/bin/env python3
'''
Script for executing SAT Attack on TRAP logic locking using Glucose4 (PySAT) Pure Boolean Solver.
Replaces Z3 SMT Solver with Glucose4 CDCL SAT Solver.

Author:     Antigravity / Pure SAT Framework
Python:     3.10+
'''

import os
import sys
import time
import re
import csv
import logging
import argparse
from z3 import *
import pysat.solvers

# Add TRAP_for_SAT_2025 directory to sys.path for VS Code Pylance & runtime resolution
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_workspace = os.path.dirname(base_dir)
trap_2025_dir = os.path.join(parent_workspace, 'TRAP_for_SAT_2025')

for k in list(sys.modules.keys()):
    if k == 'src' or k.startswith('src.'):
        del sys.modules[k]
sys.path.insert(0, trap_2025_dir)

import src.satAttack as _sa
readZ3pl = _sa.readZ3pl
writeZ3pl = _sa.writeZ3pl
copyCircuit = _sa.copyCircuit
queryOracle = _sa.queryOracle

def parsePL(ioCSV):
    inVars = []
    keyVars = []
    outVars = []
    hiZVars = {}
    with open(ioCSV, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            ioNm, ioAtts = row[0], row[1:]
            if ioAtts[0] == 'input':
                inVars.append(ioNm)
            elif ioAtts[0] == 'key':
                keyVars.append(ioNm)
            elif ioAtts[0] == 'output':
                outVars.append(ioNm)
                if len(ioAtts) > 1:
                    hiZVars[ioNm] = ioAtts[1]
    return inVars, keyVars, outVars, hiZVars

def is_greater_3bit(B2, B1, B0, A2, A1, A0):
    t1 = And(B2, Not(A2))
    t2 = And(B2 == A2, B1, Not(A1))
    t3 = And(B2 == A2, B1 == A1, B0, Not(A0))
    return Or(t1, t2, t3)

def z3ToPySAT(vars_dict, clauses_list):
    '''
    Converts Z3 PL clauses into PySAT CNF clauses and variable mapping.
    '''
    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['And'] = And
    exec_ctx['Or'] = Or
    exec_ctx['Not'] = Not
    exec_ctx['Implies'] = Implies
    exec_ctx['Xor'] = Xor
    exec_ctx['Bool'] = Bool

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
    pysat_clauses = []

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

    for clause in cnf:
        if is_or(clause):
            c = [get_lit_id(arg) for arg in clause.children()]
        else:
            c = [get_lit_id(clause)]
        pysat_clauses.append(c)

    return pysat_clauses, var_map, id_to_var

def runGlucose4(plFile: str, inVars: list) -> tuple:
    '''
    Solves a Z3 PL file using Glucose4 CDCL SAT Solver from PySAT.
    Returns (sat_boolean, extracted_inputs_dict).
    '''
    vars_dict, clauses_list = readZ3pl(plFile)
    pysat_clauses, var_map, id_to_var = z3ToPySAT(vars_dict, clauses_list)

    with pysat.solvers.Glucose4(bootstrap_with=pysat_clauses) as solver:
        sat_res = solver.solve()
        if not sat_res:
            return False, {}
        
        model = solver.get_model()
        model_dict = {}
        for lit in model:
            var_id = abs(lit)
            if var_id in id_to_var:
                model_dict[id_to_var[var_id]] = (lit > 0)
        
        extracted_ins = {}
        for inv in inVars:
            if inv in model_dict:
                extracted_ins[inv] = model_dict[inv]
            else:
                extracted_ins[inv] = False
        
        return True, extracted_ins

def buildPureMiter(trgtPL: str, inVars: list, keyVars: list, outVars: list, miterFile: str, hiZVars={}):
    '''
    Builds the initial Miter circuit file with Tri-State support.
    '''
    plVars, plClauses = readZ3pl(trgtPL)
    miterVars = {}
    miterClauses = []
    
    for i in range(1, 3):
        copy, copyVars = copyCircuit(plClauses, plVars, inVars, keyVars, outVars, suffix=f'_m{i}', modIns=False, modKeys=False)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=f'_{i}', modIns=False, modOuts=False, modNets=False)
        miterVars = miterVars | {k: v for k, v in copyVars.items() if k not in miterClauses}
        miterClauses.extend(copy)

    outSubclauses = []
    if hiZVars == {}:
        for var in outVars:
            outSubclauses.append(f'Xor({var}_m1,{var}_m2)')
    else:
        for outVar, hiZVar in hiZVars.items():
            outSubclauses.append(f'And(Xor({outVar}_m1,{outVar}_m2),Or({hiZVar}_m1,{hiZVar}_m2))')
    miterClauses.append(f'Or({",".join(outSubclauses)})')

    writeZ3pl(miterVars, miterClauses, miterFile, prnt=False)

def appendPureMiter(copyTrgt: str, DIP: dict, oracleOut: dict, inVars: list, keyVars: list, outVars: list, miterFile: str, suff: str, hiZVars={}):
    '''
    Appends DIP Oracle output constraints and Input Blocking Clauses to miterFile.
    '''
    plVars, plClauses = readZ3pl(copyTrgt)
    coupleVars = {}
    coupleCopy = []
    
    for i in range(1, 3):
        copy, copyVars = copyCircuit(plClauses, plVars, inVars, keyVars, outVars, suffix=f'{suff}_{i}', modIns=False, modKeys=False, modOuts=False)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=suff, modKeys=False, modNets=False)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=f'_{i}', modIns=False, modNets=False, modOuts=False)
        coupleVars = coupleVars | {k: v for k, v in copyVars.items() if k not in coupleCopy}
        coupleCopy.extend(copy)

    ioList = DIP | oracleOut
    for var, val in ioList.items():
        varSuff = f'{var}{suff}'
        coupleCopy.append(f'{varSuff} == {val}')

    if hiZVars != {}:
        for var in hiZVars.values():
            coupleCopy.append(f'{var}{suff}_1 == True')
            coupleCopy.append(f'{var}{suff}_2 == True')

    # Input Blocking Clause (Prevents duplicate DIPs)
    blockTerms = [f'{var} == False' if val == True else f'{var} == True' for var, val in DIP.items()]
    coupleCopy.append(f'Or({",".join(blockTerms)})')

    writeZ3pl(coupleVars, coupleCopy, miterFile, append=True, prnt=False)

def appendPureDIPCircuit(copyTrgt: str, DIP: dict, oracleOut: dict, inVars: list, keyVars: list, outVars: list, dipFile: str, suff: str, hiZVars={}):
    '''
    Appends DIP circuit copy for final key solve with output drive validity.
    '''
    plVars, plClauses = readZ3pl(copyTrgt)
    copy, copyVars = copyCircuit(plClauses, plVars, inVars, keyVars, outVars, suffix=suff, modIns=False, modKeys=False, modOuts=False)
    
    ioList = DIP | oracleOut
    for var, val in ioList.items():
        copy.append(f'{var}{suff} == {val}')

    if hiZVars != {}:
        for var in hiZVars.values():
            copy.append(f'{var}{suff} == True')

    writeZ3pl(copyVars, copy, dipFile, append=True, prnt=False)

def pysatAttack(plLogicFile: str, ioCSVFile: str, oracleNetlist: str, benchName='bench', fresh=False):
    '''
    Main SAT Attack execution routine using Glucose4 (PySAT).
    '''
    t_start = time.time()

    work_path = os.path.join(base_dir, 'work')
    logs_path = os.path.join(base_dir, 'logs')
    os.makedirs(work_path, exist_ok=True)
    os.makedirs(logs_path, exist_ok=True)

    timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(logs_path, f'pysatAttack_{timestamp}.log')

    # Setup logger for both console and log file
    logger = logging.getLogger("PureSAT")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    fh = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%m/%d/%Y %H:%M:%S'))
    logger.addHandler(fh)

    def log_print(msg):
        print(msg)
        sys.stdout.flush()
        logger.info(msg)

    miterFile = os.path.join(work_path, 'miter.py')
    dipCircuitsFile = os.path.join(work_path, 'dipCircuits.py')

    if fresh:
        for f in [miterFile, dipCircuitsFile]:
            if os.path.exists(f): os.remove(f)

    # Initialize empty dipCircuitsFile
    writeZ3pl({}, [], dipCircuitsFile, prnt=False)

    # Parse PL file
    inVars, keyVars, outVars, hiZVars = parsePL(ioCSVFile)

    log_print(f"================================================================================")
    log_print(f"STARTING PURESAT (GLUCOSE4) ATTACK: {benchName}")
    log_print(f"Target logic file: {plLogicFile}")
    log_print(f"Inputs ({len(inVars)}): {inVars} | Keys ({len(keyVars)}) | Outputs ({len(outVars)}): {outVars}")
    log_print(f"Log file: {log_file}")
    log_print(f"================================================================================\n")

    # Build initial miter
    buildPureMiter(plLogicFile, inVars, keyVars, outVars, miterFile, hiZVars=hiZVars)

    allDIPs = []
    iters = 1
    maxRounds = (2 ** len(inVars)) + 1

    while iters < maxRounds:
        log_print(f"Running Glucose4 CDCL SAT Solver on Miter clauses, round #{iters}...")
        sat, dip = runGlucose4(miterFile, inVars)

        if not sat:
            log_print(f"Miter circuit UNSATISFIED at round #{iters} (UNSAT). All valid DIPs explored!")
            break

        log_print(f"SAT! Extracted DIP #{iters}: {dip}")
        allDIPs.append(dip)

        # Query Oracle
        oracleOut = queryOracle(dip, oracleNetlist, inVars, outVars, oracleSel=True)

        # Append Miter and DIP Circuit
        appendPureMiter(plLogicFile, dip, oracleOut, inVars, keyVars, outVars, miterFile, suff=f'_cp{iters}', hiZVars=hiZVars)
        appendPureDIPCircuit(plLogicFile, dip, oracleOut, inVars, keyVars, outVars, dipCircuitsFile, suff=f'_cp{iters}', hiZVars=hiZVars)

        iters += 1

    # Solve final key
    log_print(f"\nSolving final key using Glucose4 on {len(allDIPs)} DIP constraints...")
    key_sat, key_model = runGlucose4(dipCircuitsFile, keyVars)

    if not key_sat:
        log_print("ERROR: Final Key Solve returned UNSAT!")
        return False, 0.0, 0

    key_out_file = os.path.join(work_path, 'extracted_key.csv')
    with open(key_out_file, 'w', newline='') as f:
        writer = csv.writer(f)
        for k, v in key_model.items():
            writer.writerow([k, v])

    t_duration = time.time() - t_start
    log_print(f"\nGLUCOSE4 SAT ATTACK SUCCESSFUL!")
    log_print(f"Extracted Key saved to: {key_out_file}")
    log_print(f"Total Rounds: {len(allDIPs)} | Total Time: {t_duration:.2f} seconds")
    log_print(f"================================================================================\n")

    return True, t_duration, len(allDIPs)

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: pysatAttack.py <plFile> <ioCSV> <oracleFile> <benchName> [-f]")
        sys.exit(1)
    plF = sys.argv[1]
    ioF = sys.argv[2]
    oraF = sys.argv[3]
    bName = sys.argv[4]
    frsh = '-f' in sys.argv
    pysatAttack(plF, ioF, oraF, bName, fresh=frsh)
