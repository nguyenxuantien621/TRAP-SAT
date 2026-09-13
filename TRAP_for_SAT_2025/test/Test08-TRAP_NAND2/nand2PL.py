#!/usr/bin/env python3
from z3 import *

a = Bool('a')
b = Bool('b')
o = Bool('o')

c1 = (o == Not(And(a,b)))

s = Solver()
s.add(c1)

print(s.check())
print(s.model())
