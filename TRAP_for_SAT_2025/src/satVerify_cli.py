'''
Command-line interface for satVerify.py

Author:     Aric Fowler
'''
import argparse
from .satVerify import satVerify

def main():
    parser = argparse.ArgumentParser(prog='satVerify',description='A tool for verifying an extracted key')
    parser.add_argument('extractedKeyCSV',type=str)
    parser.add_argument('goldenOraclePL',type=str)
    parser.add_argument('ioCSV',type=str)
    clArgs = parser.parse_args()

    satVerify(clArgs.extractedKeyCSV,clArgs.goldenOraclePL,clArgs.ioCSV)

if __name__ == '__main__':
    exit(main())
