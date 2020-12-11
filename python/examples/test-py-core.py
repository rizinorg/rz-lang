# Example Python Core plugin written in Python
# ===========================================
#  -- pancake 2016
#
# $ rz -I test-py-core.py -
# > q
# Dont be rude
# > ^D
# $

import rzlang

def pycore(a):
	def _call(s):
		if s == "q":
			print("Dont be rude")
			return 1;
		return 0

	return {
		"name": "PyCore",
		"license": "GPL",
		"desc": "core plugin in python",
		"call": _call,
	}

print("Registering Python core plugin...")
print(rzlang.plugin("core", pycore))
