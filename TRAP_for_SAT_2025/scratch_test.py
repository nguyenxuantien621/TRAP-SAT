from src.satAttack import readZ3pl, copyCircuit, writeZ3pl

def test_append_fixed():
    plVars, plClauses = readZ3pl('test/Test08-TRAP_NAND2/trapNAND2.py')
    inVars, keyVars, outVars = ['a','b'], [], ['o']
    suff = '_cp1'
    coupleVars = {}
    coupleCopy = []
    for i in range(1,3):
        copy, copyVars = copyCircuit(plClauses, plVars, inVars, keyVars, outVars, suffix=f'{suff}_{i}', modIns=False, modKeys=False, modOuts=False)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=suff, modKeys=False, modNets=False)
        copy, copyVars = copyCircuit(copy, copyVars, inVars, keyVars, outVars, suffix=f'_{i}', modIns=False, modNets=False, modOuts=False)
        coupleVars = coupleVars | {k:v for k,v in copyVars.items() if k not in coupleCopy}
        coupleCopy.extend(copy)

    print('o_cp1 in coupleVars:', 'o_cp1' in coupleVars)
    print('a_cp1 in coupleVars:', 'a_cp1' in coupleVars)
    print('b_cp1 in coupleVars:', 'b_cp1' in coupleVars)

test_append_fixed()
