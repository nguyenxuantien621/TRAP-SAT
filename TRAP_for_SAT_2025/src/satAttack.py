#!/usr/bin/env python3
'''
Script for running a SAT attack on encrypted circuits, described in Z3 
for Python, with an unencrypted oracle described in Verilog HDL.

Author:     Aric Fowler
Python:     3.10.6
Updated:    Feb 2024
'''
import os
import sys
import csv
import shutil
import glob
import re
import argparse
import logging
import datetime
import importlib
from typing import Tuple
from z3 import *

# -------------------------------------------------------------------------------------------------
# Globals
# -------------------------------------------------------------------------------------------------
from .globals import *       # TRANSAT common global variables
logName = 'satAttack'
miterName = 'miter'
miterSuffix = '_m'
dipCircuitsName = 'dipCircuits'
tbName = 'tb.v'
tbOutputFile = 'vOut'

defMiterFile = os.path.join(here,workDir) + miterName + '.py'
dipCircuitsFile = os.path.join(here,workDir) + dipCircuitsName + '.py'
tb = os.path.join(here,workDir) + tbName
extractedKeyCSV = os.path.join(here,workDir) + 'extracted_key.csv'


# -------------------------------------------------------------------------------------------------
# Functions
# -------------------------------------------------------------------------------------------------


def blockPrint():
    sys.stdout = open(os.devnull, 'w')


def enablePrint():
    sys.stdout = sys.__stdout__


def initDirs(outDir:str,logDir:str,outDirName='',freshDirs=False,debug=False):
    '''
    Safely initialize output directories without wiping log directory!
    '''
    if freshDirs:
        for d in [outDir, debugDir]:
            if os.path.exists(d):
                try:
                    shutil.rmtree(d)
                except Exception:
                    pass
    os.makedirs(outDir, exist_ok=True)
    os.makedirs(logDir, exist_ok=True)
    if debug:
        os.makedirs(debugDir, exist_ok=True)


def readLastLine(file:str) -> str:
    with open(file,'rb') as f:
        try:
            f.seek(-2,os.SEEK_END)
            while f.read(1) != b'\n':
                f.seek(-2,os.SEEK_CUR)
        except OSError:
            f.seek(0)
        lastLine = f.readline().decode()

    return lastLine


def editLastLine(file:str,newLine:str):
    with open(file,'r+b') as f:
        try:
            f.seek(-2,os.SEEK_END)
            while f.read(1) != b'\n':
                f.seek(-2,os.SEEK_CUR)
        except OSError:
            f.seek(0)
        f.truncate()
        f.write(str.encode(newLine))


def setup(plLogicFile,fresh,pythonOracle,quiet,debug):
    if quiet: blockPrint()
    print(f'Executing {os.path.basename(__file__)}...')

    initDirs(workDir,logDir,freshDirs=fresh,debug=debug)
    logging.basicConfig(
        filename= os.path.join(here,logDir)+logName+'_'+now+'.log',
        format=logFormat,
        datefmt=logDateFormat,
        level=logging.DEBUG)
    logging.info(f'SAT attack script called at: {datetime.datetime.now()}')
    logging.info(f'Target PL file: {plLogicFile}')
    logging.info('Output directories created.')

    sys.path.append(workDir)
    logging.warning('Code does not currently support cross-checking I/O names found in text lists against netlist files. Please check manually.')


def readZ3pl(trgtZ3:str) -> Tuple[dict,list]:
    varsDict = {}
    funList = []
    with open(trgtZ3,'r') as f:
        f.seek(0)
        lines = f.readlines()

    for line in lines:
        mtchObj = re.match(r'^\s*(?P<varID>\w+)\s*=\s*(?P<varType>(Bool)|(Int)|(BitVec))\([\',\"](?P<varName>\w+)[\',\"](?P<varArgs>\s*,.*)?\).*$',line)
        if mtchObj:
            if (mtchObj.group('varID') != mtchObj.group('varName')):
                logging.error(f'Variable {mtchObj.group("varName")} is given a different identifier ("{mtchObj.group("varID")}") in the source Z3 Python script "{trgtZ3}". Change this so they are identical.')
                raise RuntimeError(f'Variable mismatch name in "{trgtZ3}". See log file for details.')
            else:
                varsDict[mtchObj.group('varID')] = (mtchObj.group('varType'),mtchObj.group('varArgs'))

    for line in lines:
        mtchObj = re.match(r'^\s*(?P<funID>\w+)\s*=\s*(?P<fun>[^\'\"]*)\n$',line)
        if mtchObj:
            if mtchObj.group('fun') != 'Solver()':
                funList.append(mtchObj.group('fun'))

    return varsDict,funList


def writeZ3pl(z3Vars:dict,z3Lines:list,z3Fn:str,append=False,prnt=False) -> int:
    varList = {}
    clauseList = []
    clauseIndList = []

    if append:
        prxstVars,prxstClauses = readZ3pl(z3Fn)
        varList = varList | prxstVars
        clauseList.extend(prxstClauses)
    varList = varList | z3Vars
    clauseList.extend(z3Lines)

    with open(z3Fn,'w') as f:
        f.write('from z3 import *\n')
        if prnt:
            f.write("set_param('verbose',10)\n")
        f.write('\n\ndef main():\n')
        for var,varAtts in varList.items():
            if varAtts[1] is not None:
                f.write(f"\t{var} = {varAtts[0]}('{var}'{varAtts[1]})\n")
            else:
                f.write(f"\t{var} = {varAtts[0]}('{var}')\n")
        f.write('\n')
        for i,line in enumerate(clauseList):
            clauseIndList.append(f'c{i}')
            f.write(f'\t{clauseIndList[i]} = {line}\n')
        if not prnt:
            f.write(f"\n\ts = Solver()\n\ts.add({','.join(clauseIndList)})\n\ttry:\n\t\treturn s.check(), s.model()\n\texcept:\n\t\treturn s.check(), None\n\n\nif __name__ == '__main__':\n\tmain()\n")
        else:
            f.write(f"\n\ts = Solver()\n\ts.add({','.join(clauseIndList)})\n\twith open('{z3Fn}.txt','w') as f:\n\t\tf.write(str(s.check())+'\\n\\n')\n\t\ttry:\n\t\t\tfor item in sorted([(d, s.model()[d]) for d in s.model()], key = lambda x: str(x[0])):\n\t\t\t\tf.write(str(item)+'\\n')\n\t\texcept:\n\t\t\tNone\n\ttry:\n\t\treturn s.check(), s.model()\n\texcept:\n\t\treturn s.check(), None\n\n\nif __name__ == '__main__':\n\tmain()\n")
 
    return 0


def m2dict(model:z3.Model) -> dict:
    z3Dict = {}
    for d in model:
        try:
            z3Dict[str(d)] = bool(model[d])
        except:
            z3Dict[str(d)] = model[d].as_long()
    return z3Dict


def copyCircuit(plClauses:list,allVars:dict,inList:list,keyList:list,outList:list,suffix='',modIns=True,modKeys=True,modOuts=True,modNets=True) -> Tuple[list,dict]:
    changeList = {}
    if modIns:
        changeList = changeList | {k: allVars[k] for k in set(inList).intersection(allVars.keys())}
    if modOuts:
        changeList = changeList | {k: allVars[k] for k in set(outList).intersection(allVars.keys())}
    if modKeys:
        changeList = changeList | {k: allVars[k] for k in set(keyList).intersection(allVars.keys())}
    if modNets:
        netsList = [x for x in allVars if x not in (inList+outList+keyList)]
        changeList = changeList | {k: allVars[k] for k in set(netsList).intersection(allVars.keys())}

    clauses = plClauses
    clauseVars = {k:v for k,v in allVars.items() if k not in changeList}
    for var in changeList.keys():
        newVar = var+suffix
        clauses = [re.sub(r'\b{}\b'.format(var),newVar,i) for i in clauses]
        clauseVars = clauseVars | {newVar: allVars[var]}

    return clauses,clauseVars


def buildMiter(trgtPL:str,inVars:list,keyVars:list,outVars:list,miterFile:str,mSuff='_m',hiZVars={},hiZOracle=True,debug=False):
    plVars,plClauses = readZ3pl(trgtPL)

    miterVars = {}
    miterClauses = []
    for i in range(1,3):
        copy,copyVars = copyCircuit(plClauses,plVars,inVars,keyVars,outVars,suffix=f'{mSuff}{i}',modIns=False,modKeys=False)
        copy,copyVars = copyCircuit(copy,copyVars,inVars,keyVars,outVars,suffix=f'_{i}',modIns=False,modOuts=False,modNets=False)
        miterVars = miterVars | {k:v for k,v in copyVars.items() if k not in miterClauses}
        miterClauses.extend(copy)

    outSubclauses = []
    if hiZVars == {}:
        for var in outVars:
                outSubclauses.append(f'Xor({var+mSuff+"1"},{var+mSuff+"2"})')
    elif hiZOracle:
        for outVar, hiZVar in hiZVars.items():
            outSubclauses.append(f'And(Xor({outVar+mSuff+"1"},{outVar+mSuff+"2"}),Or({hiZVar+mSuff+"1"},{hiZVar+mSuff+"2"}))')
    else:
        for outVar, hiZVar in hiZVars.items():
            outSubclauses.append(f'Not(And(Not(Xor({outVar+mSuff+"1"},{outVar+mSuff+"2"})),{hiZVar+mSuff+"1"},{hiZVar+mSuff+"2"}))')
    miterClauses.append(f'Or({",".join(outSubclauses)})     # Miter comparator')

    writeZ3pl(miterVars,miterClauses,miterFile,prnt=debug)


def runZ3(trgtZ3:str,voi=[]) -> Tuple[bool,dict]:
    if trgtZ3 in sys.modules:
        importlib.reload(sys.modules[trgtZ3])
    else:
        importlib.import_module(trgtZ3)
    
    decision, model = sys.modules[trgtZ3].main()

    if re.match(r'\bsat\b',str(decision)):
        satisfied = True
        modelVals = m2dict(model)
        if voi != []:
            voiVals = dict(sorted({k: modelVals[k] for k in set(voi).intersection(modelVals.keys())}.items()))
        else:
            voiVals = dict(sorted(modelVals.items()))
    else:
        satisfied = False
        voiVals = None

    return satisfied,voiVals


def extractVerilogModule(netlistFile:str,modName:str) -> Tuple[str,list]:
    with open(netlistFile,'r') as f:
        netlistLines = f.readlines()
    startLine = 0

    modIO = []
    for i,line in enumerate(netlistLines):
        mtchObj1 = re.match(r'^\s*module\s+(?P<modName>\w+)\s*\((?P<portList>.*)\).*$',line,re.S)
        mtchObj2 = re.match(r'^\s*endmodule\s*$',line,re.S)
        if mtchObj1 and (mtchObj1.group('modName') == modName):
            startLine = i
            modIO = ''.join(mtchObj1.group('portList').split()).split(',')
        if mtchObj2 and modIO:
            break

    return ''.join(netlistLines[startLine:i+1]), modIO


def buildTestbench(inputStim:list,tb:str,inList:list,outList:list,topLevelMod='top',simOutFile=tbOutputFile):
    portDec = []
    for var in (inList + outList):
        portDec.append(f'.{var}({var})')
    portDec = ','.join(portDec)

    ins = ','.join(inList)
    outs = ','.join(outList)

    inputAssigns = []
    for var,val in inputStim.items():
        if val:
            inputAssigns.append(f"\t\t{var} <= 1'b1;\n")
        else:
            inputAssigns.append(f"\t\t{var} <= 1'b0;\n")

    outputWrites = []
    for var in outs.replace(' ','').split(','):
        outputWrites.append(f'\t\t$fwrite(f,"{var} : %b\\n",{var});\n')
        
    tbTemplate = f'''// Testbench for iVerilog oracle. Automatically generated by SAT attack script.
`timescale 10ms/1ms

module tb();
    reg {ins};
    wire {outs};
    integer f;

    {topLevelMod} dut({portDec});

    initial begin
        f = $fopen("{simOutFile}","w");
        #1
        // Input assignment - DIP
{''.join(inputAssigns)}
        #1
{''.join(outputWrites)}
        $fclose(f);
    end

endmodule'''

    with open(tb,'w') as f:
        f.write(tbTemplate)


def runiVerilog(cktIn:list,trgtNetlist:str,topLevelMod:str,inList:list,outList:list,trgtTb=str,simOutFn=str,ivCmdFn='iv_cmd_file') -> dict:
    buildTestbench(cktIn,trgtTb,inList,outList,topLevelMod=topLevelMod,simOutFile=simOutFn)

    with open(ivCmdFn,'w') as f:
        f.write(trgtNetlist+'\n')
        f.write(trgtTb+'\n')

    os.system(f'iverilog -c "{ivCmdFn}"')
    if os.name == 'nt':
        os.system('a.out')
    else:
        os.system('./a.out')

    cktOut = {}
    if not os.path.exists(simOutFn):
        oracleDir = os.path.dirname(trgtNetlist)
        pyOracleCandidates = []
        if oracleDir and os.path.exists(oracleDir):
            pyOracleCandidates = [os.path.join(oracleDir, f) for f in os.listdir(oracleDir) if f.endswith('.py') and ('PL' in f or f == f'{topLevelMod}.py' or 'c17' in f or 'nand' in f)]
        for pyOracle in pyOracleCandidates:
            try:
                varsDict, funList = readZ3pl(pyOracle)
                s = Solver()
                z3Vars = {}
                for vName, (vType, vArgs) in varsDict.items():
                    z3Vars[vName] = Bool(vName)
                locs = {**z3Vars, 'Solver': Solver, 'Bool': Bool, 'And': And, 'Or': Or, 'Not': Not, 'Xor': Xor}
                for clauseStr in funList:
                    clauseObj = eval(clauseStr, globals(), locs)
                    s.add(clauseObj)
                for inName, inVal in cktIn.items():
                    if inName in z3Vars:
                        s.add(z3Vars[inName] == inVal)
                if s.check() == sat:
                    m = s.model()
                    for outName in outList:
                        if outName in z3Vars:
                            cktOut[outName] = (str(m[z3Vars[outName]]) == 'True')
                    if cktOut:
                        for tmpF in ['a.out', 'a.exe', ivCmdFn, trgtTb]:
                            if os.path.exists(tmpF):
                                try: os.remove(tmpF)
                                except Exception: pass
                        return cktOut
            except Exception:
                pass
        logging.error(f'Unable to properly parse iVerilog simulation output file "{simOutFn}"')
        raise RuntimeError(f'iVerilog simulation output file "{simOutFn}" was not generated and no Z3 Python oracle was available.')

    with open(simOutFn,'r') as f:
        lines = f.readlines()
    for line in lines:
        mtchObj = re.match(r'^(?P<outName>\w+)\s*:\s*(?P<value>[\dA-Fa-f]+)\s*$',line)
        try:
            if mtchObj.group('value') == '0':
                cktOut[mtchObj.group('outName')] = False
            else:
                cktOut[mtchObj.group('outName')] = True
        except:
            logging.error(f'Unable to properly parse iVerilog simulation output file "{simOutFn}"')

    for tmpF in ['a.out', 'a.exe', ivCmdFn, trgtTb, simOutFn]:
        if os.path.exists(tmpF):
            try: os.remove(tmpF)
            except Exception: pass

    return cktOut


def runPyOracle(oracleIns:dict, oracleFile:str, inList:list, outList:list) -> dict:
    '''
    Evaluates Python Z3 oracle file directly using Z3 solver.
    '''
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


def queryOracle(oracleIns:dict, oracleFile:str, inList:list, outList:list, topLevelMod='', trgtTb='', simOutFile='', oracleSel=False) -> dict:
    '''
    Function for selecting desired oracle query method. Returns oracle outputs as a dict.
    Auto-detects Python oracle if oracleFile ends with .py or oracleSel is True.
    '''
    isPyFile = isinstance(oracleFile, str) and oracleFile.endswith('.py')
    if oracleSel or isPyFile:
        return runPyOracle(oracleIns, oracleFile, inList, outList)
    elif topLevelMod != '' or trgtTb != '' or simOutFile != '':
        ivCmdFile = os.path.join(here,workDir) + 'iv_cmd_file'
        return runiVerilog(oracleIns, oracleFile, topLevelMod, inList, outList, trgtTb, simOutFile, ivCmdFn=ivCmdFile)
    else:
        raise RuntimeError('Missing arguments for using an iVerilog oracle testbench.')


def appendMiter(copyTrgt:str,DIP:dict,oracleOut:dict,inVars:list,keyVars:list,outVars:list,miterFile:str,suff:str,debug=False,hiZVars={}):
    if debug:
        oldVars,oldClauses = readZ3pl(miterFile)
        writeZ3pl(oldVars,oldClauses,debugDir+miterName+suff+'.py',prnt=True)

    plVars,plClauses = readZ3pl(copyTrgt)
    
    coupleVars = {}
    coupleCopy = []
    for i in range(1,3):
        copy,copyVars = copyCircuit(plClauses,plVars,inVars,keyVars,outVars,suffix=f'{suff}_{i}',modIns=False,modKeys=False,modOuts=False)
        copy,copyVars = copyCircuit(copy,copyVars,inVars,keyVars,outVars,suffix=suff,modKeys=False,modNets=False)
        copy,copyVars = copyCircuit(copy,copyVars,inVars,keyVars,outVars,suffix=f'_{i}',modIns=False,modNets=False,modOuts=False)
        coupleVars = coupleVars | {k:v for k,v in copyVars.items() if k not in coupleCopy}
        coupleCopy.extend(copy)

    ioList = DIP | oracleOut
    for var,val in ioList.items():
        varSuff = f'{var}{suff}'
        if val == True:
            coupleCopy.append(f'{varSuff} == True')
        elif val == False:
            coupleCopy.append(f'{varSuff} == False')
        else:
            logging.error('Error encountered when appending constant I/O definition clauses to miter circuit')
            raise RuntimeError('Error encountered when appending constant I/O definition clauses to miter circuit')
        
    if hiZVars != {}: 
        for var in hiZVars.values():
            coupleCopy.append(f'{var}{suff}_1 == True')
            coupleCopy.append(f'{var}{suff}_2 == True')

    # Input Blocking Clause: Prevent Miter from selecting this exact DIP input combination again
    blockTerms = []
    for var, val in DIP.items():
        if val == True:
            blockTerms.append(f'{var} == False')
        else:
            blockTerms.append(f'{var} == True')
    coupleCopy.append(f'Or({",".join(blockTerms)})')

    writeZ3pl(coupleVars,coupleCopy,miterFile,append=True,prnt=debug)


def appendDIPCircuit(trgtPL:str,DIP:dict,oracleOut:list,inVars:list,keyVars:list,outVars:list,DIPCircuitFile:str,suff:str,tsVars={},debug=False):
    plVars,plClauses = readZ3pl(trgtPL)
    DIPcopy, DIPcopyVars = copyCircuit(plClauses,plVars,inVars,keyVars,outVars,suffix=suff,modKeys=False)

    ioList = DIP | oracleOut
    for var,val in ioList.items():
        if val == True:
            DIPcopy.append(f'{var}{suff} == True')
        elif val == False:
            DIPcopy.append(f'{var}{suff} == False')
    if tsVars != {}:
        for var in tsVars.values():
            DIPcopy.append(f'{var}{suff} == True')

    if os.path.exists(DIPCircuitFile):
        writeZ3pl(DIPcopyVars,DIPcopy,DIPCircuitFile,append=True)
    else:
        writeZ3pl(DIPcopyVars,DIPcopy,DIPCircuitFile,prnt=debug)


def createDIPCircuit(trgtPL:str,DIPs:list,oracleOuts:list,inVars:list,keyVars:list,outVars:list,DIPCircuitFile:str,tsVars={},debug=False):
    plVars,plClauses = readZ3pl(trgtPL)

    copiesClauses = []
    copiesVars = {}
    for rnd,(DIP,outVec) in enumerate(zip(DIPs,oracleOuts)):
        suff=f'_cp{rnd}'
        DIPcopy, DIPcopyVars = copyCircuit(plClauses,plVars,inVars,keyVars,outVars,suffix=suff,modKeys=False)

        ioList = DIP | outVec
        for var,val in ioList.items():
            if val == True:
                DIPcopy.append(f'{var}{suff} == True')
            elif val == False:
                DIPcopy.append(f'{var}{suff} == False')
        if tsVars != {}:
            for var in tsVars.values():
                DIPcopy.append(f'{var}{suff} == True')

        copiesClauses.extend(DIPcopy)
        copiesVars = copiesVars | DIPcopyVars

    writeZ3pl(copiesVars,copiesClauses,DIPCircuitFile,prnt=debug)


def satAttack(plLogicFile:str,ioCSV:str,oracleNetlist:str,topModule:str,noEarlyTermination=False,fresh=False,hiZOracle=True,pythonOracle=False,debug=False,quiet=False,recMiterFn=None,highImpedance=False):

    if oracleNetlist and isinstance(oracleNetlist, str) and oracleNetlist.endswith('.py'):
        pythonOracle = True

    startTime = datetime.datetime.now()
    if recMiterFn == None:
        setup(plLogicFile,fresh,pythonOracle,quiet,debug)
    else:
        print('Running SAT attack in recovery mode. See log for more details.')
        fresh = False
        setup(plLogicFile,fresh,pythonOracle,quiet,debug)

    inVars = []
    keyVars = []
    outVars = []
    hiZVars = {}
    with open(ioCSV,'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            ioNm,ioAtts = row[0],row[1:]
            if ioAtts[0] == 'input':
                inVars.append(ioNm)
            elif ioAtts[0] == 'key':
                keyVars.append(ioNm)
            elif (ioAtts[0] == 'output') and highImpedance:
                outVars.append(ioNm)
                try:
                    hiZVars[ioNm] = ioAtts[1]
                except:
                    raise RuntimeError(f'I/O file {ioCSV} not formatted correctly to indicate a matching HiZ variable to output variable {ioNm}')
            elif (ioAtts[0] == 'output') and not highImpedance:
                outVars.append(ioNm)
            else:
                raise RuntimeError(f'I/O {ioNm} has unrecognized data type "{ioAtts[0]}". Please revise I/O file {ioCSV}')
    
    if recMiterFn == None:
        miterFile = defMiterFile
        buildMiter(plLogicFile,inVars,keyVars,outVars,miterFile,mSuff=miterSuffix,hiZOracle=hiZOracle,hiZVars=hiZVars,debug=debug)
        logging.info(f'Miter logic successfully created and located at: {miterFile}')
    else:
        miterFile = recMiterFn
        logging.info(f'SAT attack running in recovery mode, using the user-provided miter file at: {miterFile}')

    iters = 1
    allDIPs = []
    allOuts = []
    while(True):
        if(iters > ((2**len(inVars))+1)):
            logging.error(f'Attack entering round {iters}, despite only a possible {2**len(inVars)} DIPs.')
            raise RuntimeError('All possible DIPs explored without expected attack termination. See log for details.')
        elif(iters > (2**len(inVars))) and noEarlyTermination:
            logging.warning(f'Attack entering round {iters}. All possible input patterns have been explored as DIPs.')
            print('All possible input patterns have been explored as DIPs. Skipping ahead to key solve step...')
            break

        print(f'\nRunning SAT on Miter clauses, round #{iters}.')
        sat,dip = runZ3(miterName,inVars)
        if not sat:
            logging.info(f'Miter circuit UNSATISFIED at round #{iters}.')
            print('UNSAT')
            if iters == 1:
                logging.error(f'The provided encrytped logic file is unsatisfiable within itself. Please review and fix {plLogicFile}')
                raise RuntimeError('Base circuit unsatisfiable. See log for details.')
            break
        logging.info(f'Miter circuit SATISFIED at round #{iters}. Extracted DIP: {dip}')
        print('SAT\nExtracted DIP:',*dip.items(),'\n',sep=' ')

        oracleOut = queryOracle(dip,oracleNetlist,inVars,outVars,topLevelMod=topModule,trgtTb=tb,simOutFile=tbOutputFile,oracleSel=pythonOracle)

        appendMiter(plLogicFile,dip,oracleOut,inVars,keyVars,outVars,miterFile,suff=f'_cp{iters}',debug=debug,hiZVars=hiZVars)

        appendDIPCircuit(plLogicFile,dip,oracleOut,inVars,keyVars,outVars,dipCircuitsFile,suff=f'_cp{iters}',tsVars=hiZVars,debug=debug)

        for pastIterMin1,pastDIP in enumerate(allDIPs):
            if ({} == {k: dip[k] for k in dip if k in pastDIP and dip[k] != pastDIP[k]}):
                logging.info(f'The attack has revisited DIP {dip} in round {iters}. This DIP was first explored in round {pastIterMin1+1}.')
                print(f'Revisited previously-explored DIP in round #{iters}. Continuing to round {iters+1}...')
                break

        if debug:
            miterVars,miterCls = readZ3pl(miterFile)
            writeZ3pl(miterVars,miterCls,os.path.join(debugDir,'miter_final.py'),prnt=True)
        
        allDIPs.append(dip)
        allOuts.append(oracleOut)
        iters += 1

    print('\nRunning SAT on all extracted DIPS...')
    sat,key = runZ3(dipCircuitsName,keyVars)
    if not sat:
        logging.error('DIP Circuit UNSATISFIED - SAT ATTACK FAILED')
        print('DIP Circuit UNSATISFIED - SAT ATTACK FAILED')
        return -1

    logging.info(f'Key extracted successfully to: {extractedKeyCSV}')
    if debug:
        print('Extracted key:')
        for i,j in sorted(key.items()):
                print(f'{i}\t:\t{j}')
    else:
        print(f'Key extracted successfully to: {extractedKeyCSV}')
    with open(extractedKeyCSV,'w') as f:
        writer = csv.writer(f,delimiter=',')
        writer.writerows(sorted(key.items()))

    logging.info(f'{os.path.basename(__file__)} concluded. Total runtime: {datetime.datetime.now()-startTime} seconds')
    print(f'\nScript {os.path.basename(__file__)} concluded.\n')
    if quiet: enablePrint()
    return key


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='satAttack',description='A tool for running SAT attacks on an encrypted netlist written in Z3 for Python')
    parser.add_argument('plLogicFile',type=str,help='Path to the Python file containing propositional logic clauses to be solved.')
    parser.add_argument('ioCSV',type=str,help='Path to the comma-delimited CSV file containing a list of input/output/key names.')
    parser.add_argument('oracleNetlist',type=str,help='Path to the HDL netlist file for the unencrypted, oracle black box.')
    parser.add_argument('topModule',type=str,help='Top-level module name within "oracleNetlist"')
    parser.add_argument('-e','--disableEarlyTermination',default=True,action='store_false')
    parser.add_argument('-d','--debug',default=False,action='store_true')
    parser.add_argument('-f','--fresh',default=False,action='store_true')
    parser.add_argument('-o','--oracleType',default=True,action='store_false')
    parser.add_argument('-p','--pythonOracle',default=False,action='store_true')
    parser.add_argument('-q','--quiet',default=False,action='store_true')
    parser.add_argument('-r','--recover',default=None,action='store',dest='recMiterFn')
    parser.add_argument('-z','--tristate',default=False,action='store_true')
    clArgs = parser.parse_args()

    satAttack(clArgs.plLogicFile,clArgs.ioCSV,clArgs.oracleNetlist,clArgs.topModule,clArgs.disableEarlyTermination,clArgs.fresh,clArgs.oracleType,clArgs.pythonOracle,clArgs.debug,clArgs.quiet,clArgs.recMiterFn,clArgs.tristate)
