'''
Command-line interface for satAttack.py

Author:     Aric Fowler
'''
import argparse
from .satAttack import satAttack

def main():
    parser = argparse.ArgumentParser(prog='satAttack',description='A tool for running SAT attacks on an encrypted netlist written in Z3 for Python')
    parser.add_argument('plLogicFile',type=str,help='Path to the Python file containing propositional logic clauses to be solved.')
    parser.add_argument('ioCSV',type=str,help='Path to the comma-delimited CSV file containing a list of input/output/key names.')
    parser.add_argument('oracleNetlist',type=str,nargs='?',default='nand2PL.py',help='Path to the HDL netlist file for the unencrypted, oracle black box.')
    parser.add_argument('topModule',type=str,nargs='?',default='nand2',help='Top-level module name within "oracleNetlist"')
    parser.add_argument('-e','--disableEarlyTermination',default=True,action='store_false',help='By default, skips the final (UNSAT) round of the attack if all possible inputs are explored as DIPs.')
    parser.add_argument('-d','--debug',default=False,action='store_true',help='Creates intermediate scripts in a "debug" directory')
    parser.add_argument('-f','--fresh',default=False,action='store_true',help='Create fresh directories for SAT attack.')
    parser.add_argument('-o','--oracleType',default=True,action='store_false',help='Indicates if the oracle can express HiZ outputs.')
    parser.add_argument('-p','--pythonOracle',default=False,action='store_true',help='If true, oraclenetlist points to a Python oracle file.')
    parser.add_argument('-q','--quiet',default=False,action='store_true',help='Prevent printing of SAT attack progress to terminal')
    parser.add_argument('-r','--recover',default=None,action='store',dest='recMiterFn',help='Point to a running miter file')
    parser.add_argument('-z','--tristate',default=False,action='store_true',help='Enables "tri-state" mode for circuit outputs.')
    clArgs = parser.parse_args()

    if clArgs.oracleNetlist and clArgs.oracleNetlist.endswith('.py'):
        clArgs.pythonOracle = True

    satAttack(clArgs.plLogicFile,clArgs.ioCSV,clArgs.oracleNetlist,clArgs.topModule,clArgs.disableEarlyTermination,clArgs.fresh,clArgs.oracleType,clArgs.pythonOracle,clArgs.debug,clArgs.quiet,clArgs.recMiterFn,clArgs.tristate)

if __name__ == '__main__':
    exit(main())
