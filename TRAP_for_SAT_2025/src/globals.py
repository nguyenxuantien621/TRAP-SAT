import os
import datetime

here = os.getcwd() + '/'
workDir = 'work/'
logDir = 'logs/'
debugDir = 'debug/'
logFormat = '%(asctime)s %(levelname)s %(filename)s: %(message)s'
logDateFormat = '%m/%d/%Y %H:%M:%S'
now = str(datetime.datetime.now()).replace(' ','_').replace(':','-').replace('.','-')

gateTypes = [
    'not',
    'and2',
    'or2',
    'nand2',
    'nor2',
    'xor2',
    'xnor2',
    'buf',
]
