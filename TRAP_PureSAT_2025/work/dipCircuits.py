from z3 import *


def main():


	s = Solver()
	s.add()
	try:
		return s.check(), s.model()
	except:
		return s.check(), None


if __name__ == '__main__':
	main()
