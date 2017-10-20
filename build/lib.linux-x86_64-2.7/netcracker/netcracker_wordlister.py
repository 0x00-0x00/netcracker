from netcracker import *
def generateEssidPasswords(essid):
	w = Word(essid)
	l = [w.lower, w.upper, w.alpha]
	for word in l:
		for y in xrange(10000):
			yield word + "%s" % (y)

def remove_numbers(string):
	output = ""
	n = [0,1,2,3,4,5,6,7,8,9]
	for char in string:
		if(char not in [str(x) for x in n]):
			output += char
	return output


def splitter(string):
	output = []
	if(" " not in string and "-" not in string and "_" not in string and string.upper() != string):
		for char in string:
			if(char != string[0:1] and char == char.upper()):
				i = string.find(char)
				output.append(string[0:i])
				output.append(string[i:])
				output.append(string)
				return output
		return remove_numbers(string)
	else:
		if(" " in string):
			return string.split(" ")
		elif("-" in string):
			return string.split("-")
		elif("_" in string):
			return string.split("_")
		elif(string.upper() == string):
			return remove_numbers(string)
