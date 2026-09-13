'''
Command-line interface for trapFabricBuilder.py

Author:     Aric Fowler
'''
import argparse
from .trapFabricBuilder import trapFabricBuilder

def main():
    parser = argparse.ArgumentParser(prog='trapFabricBuilder',description='A tool for generating a TRAP fabric model')
    parser.add_argument('numRows',type=int)
    parser.add_argument('numCols',type=int)
    parser.add_argument('pinMap',type=str)
    parser.add_argument('-d',action='store_true',dest='debug',default=False)
    parser.add_argument('-m',action='store',dest='maxCount',default=None,type=int)
    parser.add_argument('-o',action='store',dest='outputFileName',default='trapFabricPL',type=str)
    clArgs = parser.parse_args()

    trapFabricBuilder(clArgs.numRows,clArgs.numCols,clArgs.pinMap,clArgs.debug,clArgs.outputFileName,clArgs.maxCount)

if __name__ == '__main__':
    exit(main())
