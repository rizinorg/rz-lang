# Example Python Asm plugin written in Python
# ===========================================
#
#  -- pancake @ nopcode.org
#
# The rzlang.plugin function exposes a way to register new plugins
# into the RCore instance. This API is only available from RLang.
# You must call with with '#!python test.py' or 'rz -i test.py ..'

import rzlang

def pyasm(a):
	def assemble(s):
		print("Assembling %s"%(s))
		return [ 1, 2, 3, 4 ]

	def disassemble(buf, pc):
		try:
			return [ 2, f"opcode {buf[0]}" ]
		except:
			print("err")
			print(sys.exc_info())
			return [ 2, "opcode" ]
	return {
		"name": "MyPyDisasm",
		"arch": "pyarch",
		"bits": 32,
		"license": "GPL",
		"desc": "disassembler plugin in python",
		"assemble": assemble,
		"disassemble": disassemble,
	}

if not rzlang.plugin("asm", pyasm):
	print("Failed to register the python asm plugin.")

