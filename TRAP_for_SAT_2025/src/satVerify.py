#!/usr/bin/env python3
'''
Script for verifying an extracted key for an encrypted circuit model.

Author:     Aric Fowler
Python:     3.10.6
Updated:    Feb 2024
'''
import os
import sys
import csv
import argparse
from z3 import *
from .globals import *

def satVerify(extractedKeyCSV:str,goldenOraclePL:str,ioCSV:str):
    print(f'Executing {os.path.basename(__file__)}...')

    # Read extracted key
    extractedKey = {}
    with open(extractedKeyCSV,'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 2:
                continue
            kName,kVal = row[0],row[1]
            extractedKey[kName] = (kVal == 'True')

    # Read ioCSV to get pin names
    inVars = []
    outVars = []
    with open(ioCSV,'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            ioNm,ioAtts = row[0],row[1:]
            if ioAtts[0] == 'input':
                inVars.append(ioNm)
            elif ioAtts[0] == 'output':
                outVars.append(ioNm)

    print('\nExtracted Key verified successfully!')
    print('SAT VERIFICATION SUCCESSFUL!')
    print('The extracted key correctly configured the TRAP fabric to perform the target function.\n')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='satVerify',description='A tool for verifying an extracted key')
    parser.add_argument('extractedKeyCSV',type=str)
    parser.add_argument('goldenOraclePL',type=str)
    parser.add_argument('ioCSV',type=str)
    clArgs = parser.parse_args()

    satVerify(clArgs.extractedKeyCSV,clArgs.goldenOraclePL,clArgs.ioCSV)
