#!/usr/bin/env python3
'''
Propositional logic clauses describing an unencrypted (e.g. ASIC) C17. Used for 
satVerify to verify the extracted key from satAttack.
Python:     3.10.6
Updated:    Nov 2023
'''
from z3 import *

# Circuit inputs
pi1 = Bool('pi1')
pi2 = Bool('pi2')
pi3 = Bool('pi3')
pi6 = Bool('pi6')
pi7 = Bool('pi7')

# Circuit outputs
po22 = Bool('po22')
po23 = Bool('po23')

# Circuit nets
nand1 = Bool('nand1')
nand2 = Bool('nand2')
nand3 = Bool('nand3')
nand4 = Bool('nand4')
nand5 = Bool('nand5')
nand6 = Bool('nand6')

# Circuit description (PL clauses)
c1 = nand1 == Not(And(pi1,pi3))
c2 = nand2 == Not(And(pi3,pi6))
c3 = nand3 == Not(And(nand1,nand6))
c4 = nand4 == Not(And(nand6,nand5))
c5 = nand5 == Not(And(nand2,pi7))
c6 = nand6 == Not(And(nand2,pi2))

# Output clauses
c_po22 = nand3 == po22
c_po23 = nand4 == po23

# Add model to solver
s = Solver()
s.add(c1,c2,c3,c4,c5,c6,c_po22,c_po23)

print(s.check())
print(s.model())
