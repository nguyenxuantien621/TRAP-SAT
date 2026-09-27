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

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def readZ3pl(trgtZ3: str):
    varsDict = {}
    funList = []
    with open(trgtZ3, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for line in lines:
        mtchObj = re.match(r'^\s*(?P<varID>\w+)\s*=\s*(?P<varType>(Bool)|(Int)|(BitVec))\([\',\"](?P<varName>\w+)[\',\"](?P<varArgs>\s*,.*)?\).*$', line)
        if mtchObj:
            varsDict[mtchObj.group('varID')] = (mtchObj.group('varType'), mtchObj.group('varArgs'))
    for line in lines:
        mtchObj = re.match(r'^\s*(?P<funID>\w+)\s*=\s*(?P<fun>[^\'\"]*)\n$', line)
        if mtchObj and mtchObj.group('fun') != 'Solver()':
            funList.append(mtchObj.group('fun'))
    return varsDict, funList

def writeZ3pl(z3Vars: dict, z3Lines: list, z3Fn: str, append=False, prnt=False) -> int:
    varList = {}
    clauseList = []
    clauseIndList = []
    if append and os.path.exists(z3Fn):
        prxstVars, prxstClauses = readZ3pl(z3Fn)
        varList.update(prxstVars)
        clauseList.extend(prxstClauses)
    varList.update(z3Vars)
    clauseList.extend(z3Lines)
    with open(z3Fn, 'w', encoding='utf-8') as f:
        f.write('from z3 import *\n\n\ndef main():\n')
        for var, varAtts in varList.items():
            f.write(f"\t{var} = {varAtts[0]}('{var}')\n")
        f.write('\n')
        for i, line in enumerate(clauseList):
            clauseIndList.append(f'c{i}')
            f.write(f'\t{clauseIndList[i]} = {line}\n')
        f.write(f"\n\ts = Solver()\n\ts.add({','.join(clauseIndList)})\n\ttry:\n\t\treturn s.check(), s.model()\n\texcept:\n\t\treturn s.check(), None\n\n\nif __name__ == '__main__':\n\tmain()\n")
    return 0

def copyCircuit(plClauses: list, allVars: dict, inList: list, keyList: list, outList: list, suffix='', modIns=True, modKeys=True, modOuts=True, modNets=True):
    staticVars = set(keyList) | {x for x in allVars if x.startswith('DL') or x.startswith('DC') or x.startswith('cnt') or x.startswith('isInp')}
    changeList = {}
    if modIns:
        changeList.update({k: allVars[k] for k in set(inList).intersection(allVars.keys())})
    if modOuts:
        changeList.update({k: allVars[k] for k in set(outList).intersection(allVars.keys())})
    if modKeys:
        changeList.update({k: allVars[k] for k in set(staticVars).intersection(allVars.keys())})
    if modNets:
        dynNets = [x for x in allVars if x not in inList and x not in outList and x not in staticVars]
        changeList.update({k: allVars[k] for k in set(dynNets).intersection(allVars.keys())})
    clauses = plClauses
    clauseVars = {k: v for k, v in allVars.items() if k not in changeList}
    for var in changeList.keys():
        newVar = var + suffix
        clauses = [re.sub(r'\b{}\b'.format(var), newVar, i) for i in clauses]
        clauseVars[newVar] = allVars[var]
    return clauses, clauseVars

def runPyOracle(oracleIns: dict, oracleFile: str, inList: list, outList: list) -> dict:
    varsDict, funList = readZ3pl(oracleFile)
    s = Solver()
    z3Vars = {}
    for vName, (vType, vArgs) in varsDict.items():
        z3Vars[vName] = Bool(vName)
    locs = {**z3Vars, 'Solver': Solver, 'Bool': Bool, 'And': And, 'Or': Or, 'Not': Not, 'Xor': Xor}
    for clauseStr in funList:
        try:
            clauseObj = eval(clauseStr, globals(), locs)
            s.add(clauseObj)
        except Exception:
            pass
    for inName, inVal in oracleIns.items():
        if inName in z3Vars:
            s.add(z3Vars[inName] == inVal)
    cktOut = {}
    if s.check() == sat:
        m = s.model()
        for outName in outList:
            if outName in z3Vars:
                cktOut[outName] = (str(m[z3Vars[outName]]) == 'True')
    return cktOut

def queryOracle(oracleIns: dict, oracleFile: str, inList: list, outList: list, topLevelMod='', trgtTb='', simOutFile='', oracleSel=False) -> dict:
    return runPyOracle(oracleIns, oracleFile, inList, outList)

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

def build_magnitude_comparator(B_bits: list, A_bits: list):
    n = len(B_bits)
    terms = []
    for i in range(n):
        eq_prefixes = [B_bits[j] == A_bits[j] for j in range(i)]
        cur_step = And(B_bits[i], Not(A_bits[i]))
        if eq_prefixes:
            terms.append(And(*eq_prefixes, cur_step))
        else:
            terms.append(cur_step)
    return Or(*terms)

def is_greater_3bit(*args): return build_magnitude_comparator(list(args[:3]), list(args[3:]))
def is_greater_4bit(*args): return build_magnitude_comparator(list(args[:4]), list(args[4:]))
def is_greater_5bit(*args): return build_magnitude_comparator(list(args[:5]), list(args[5:]))
def is_greater_6bit(*args): return build_magnitude_comparator(list(args[:6]), list(args[6:]))
def is_greater_7bit(*args): return build_magnitude_comparator(list(args[:7]), list(args[7:]))
def is_greater_8bit(*args): return build_magnitude_comparator(list(args[:8]), list(args[8:]))

def z3ToPySAT(vars_dict, clauses_list):
    '''
    Converts Z3 PL clauses into PySAT CNF clauses and variable mapping.
    '''
    exec_ctx = {k: Bool(k) for k in vars_dict.keys()}
    exec_ctx['build_magnitude_comparator'] = build_magnitude_comparator
    exec_ctx['is_greater_3bit'] = is_greater_3bit
    exec_ctx['is_greater_4bit'] = is_greater_4bit
    exec_ctx['is_greater_5bit'] = is_greater_5bit
    exec_ctx['is_greater_6bit'] = is_greater_6bit
    exec_ctx['is_greater_7bit'] = is_greater_7bit
    exec_ctx['is_greater_8bit'] = is_greater_8bit
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
    Optimized: Filters out redundant acyclicity/cnt clauses since K1 and K2 acyclicity is already enforced in the base Miter.
    '''
    plVars, plClauses = readZ3pl(copyTrgt)
    func_clauses = [c for c in plClauses if 'is_greater_' not in c and 'cnt' not in c]
    coupleVars = {}
    coupleCopy = []
    
    for i in range(1, 3):
        copy, copyVars = copyCircuit(func_clauses, plVars, inVars, keyVars, outVars, suffix=f'{suff}_{i}', modIns=False, modKeys=False, modOuts=True, modNets=True)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=f'_{i}', modIns=False, modKeys=True, modOuts=False, modNets=False)
        coupleVars = coupleVars | {k: v for k, v in copyVars.items() if k not in coupleCopy}
        coupleCopy.extend(copy)

    ioList = DIP | oracleOut
    for var, val in ioList.items():
        coupleCopy.append(f'{var}{suff}_1 == {val}')
        coupleCopy.append(f'{var}{suff}_2 == {val}')

    if hiZVars != {}:
        for var in hiZVars.values():
            coupleCopy.append(f'{var}{suff}_1 == True')
            coupleCopy.append(f'{var}{suff}_2 == True')

    # Input Blocking Clause (Prevents duplicate DIPs)
    blockTerms = [f'{var} == False' if val == True else f'{var} == True' for var, val in DIP.items()]
    coupleCopy.append(f'Or({",".join(blockTerms)})')

    writeZ3pl(coupleVars, coupleCopy, miterFile, append=True, prnt=False)

def appendPureDIPCircuit(copyTrgt: str, DIP: dict, oracleOut: dict, inVars: list, keyVars: list, outVars: list, dipFile: str, suff: str, hiZVars={}, is_first_dip=False):
    '''
    Appends DIP circuit copy for final key solve with output drive validity.
    '''
    plVars, plClauses = readZ3pl(copyTrgt)
    if is_first_dip:
        clauses_to_copy = plClauses
    else:
        clauses_to_copy = [c for c in plClauses if 'is_greater_' not in c and 'cnt' not in c]
        
    copy, copyVars = copyCircuit(clauses_to_copy, plVars, inVars, keyVars, outVars, suffix=suff, modKeys=False)
    
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
        appendPureDIPCircuit(plLogicFile, dip, oracleOut, inVars, keyVars, outVars, dipCircuitsFile, suff=f'_cp{iters}', hiZVars=hiZVars, is_first_dip=(iters == 1))

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
