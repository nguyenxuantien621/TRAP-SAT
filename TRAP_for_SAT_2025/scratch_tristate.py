from src.satAttack import satAttack

print('--- Testing satAttack with -z (tristate mode) ---')
try:
    key = satAttack(
        plLogicFile='test/Test08-TRAP_NAND2/trapNAND2.py',
        ioCSV='test/Test08-TRAP_NAND2/trapNAND2_io.csv',
        oracleNetlist='test/Test08-TRAP_NAND2/nand2PL.py',
        topModule='nand2',
        noEarlyTermination=False,
        fresh=True,
        pythonOracle=True,
        highImpedance=True
    )
    print('Result key:', key)
except Exception as e:
    print('Caught exception:', e)
