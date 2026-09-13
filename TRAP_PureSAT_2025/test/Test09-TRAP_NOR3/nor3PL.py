#!/usr/bin/env python3
from z3 import *

a = Bool('a')
b = Bool('b')
c = Bool('c')
o = Bool('o')

c1 = (o == Not(Or(a,b,c)))

s = Solver()
s.add(c1)

print(s.check())
print(s.model())
