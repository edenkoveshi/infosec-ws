#!/usr/bin/env python
import re
import fnmatch
import os
import string

C_REGEX = []

def isCode(data):
	lines_score_sum,lines_len_sum = get_data_score(data)
	if(lines_score_sum < 0): #almost no chance to enter this,but either way this is a text file
		return False
	score = (lines_score_sum + 1)/(lines_len_sum + 1)
	'''if score > 30:
		print data'''
	return score > 1.4
	
def get_data_score(data):
	lines = data.split('\n')
	lines = list(filter(lambda x: x!=None,lines)) #delete empty lines
	num_lines = len(lines)
	lines_len_sum = 0;
	lines_score_sum = 0;
	for line in lines:
		lines_len_sum += len(line)
		lines_score_sum += get_line_score(line)
	
	return lines_score_sum,lines_len_sum

def get_line_score(line):
	#double_score_chars = ['{','}','=','<','>','+','#','*']
	high_conf = ["#include ",".h>",".h\"","#if ","#endif","NULL","0x","->","malloc","stdlib"]
	low_conf  = ["extern ","const ","static ","case "]
	score = 0
	line_len = len(line)

	if(line != ""):
		for exp in C_REGEX:
			matches = re.findall(exp,line)
			r = re.findall(r'[{}()#\\/*+\-=<>_;]{1}', line)
			for match in matches:
				score += 5.2*line_len
				#print "found regexp %s"%match
			''''for match in r:
				if(match in double_score_chars):
					score += 0.1*line_len
				else:
					score += 0.05*line_len'''
			for match in re.findall('|'.join(high_conf), line, flags=re.IGNORECASE):
				if match not in matches:
					score += 1.6*line_len
			for match in re.findall('|'.join(low_conf), line, flags=re.IGNORECASE):
				if match not in matches:
					score += 0.3*line_len

		if(line[0] == '{' or line[0] == '}'):
			score += 1.4*line_len

		if(line[-1:] == '{' or line[-1:] == '}'):
			score += 1.4*line_len

		if(line[-1:] == '.'): #text files are more likely to end with this
			score -= 0.9*line_len
				
	return score
	
def getFileStats(filenames,extension):
	correct,total = 0,0
	for filename in filenames:
		total += 1
		if(total % 50 == 0):
			print "Still running.." #sanity check every 50 files
		data = open(filename,'r').read()
		is_code = isCode(data)
		if(is_code and extension=="c"):
			correct += 1
		elif(not is_code and extension=="txt"):
			correct += 1
		'''else:
			print data'''
	success = ((float)(correct)/total)*100
	print "{} correct out of {} total ({}%)".format(correct,total,success)

def score_dir_files(path,extension):
	matches = []
	for root, dirnames, filenames in os.walk(path):
		for filename in fnmatch.filter(filenames, '*.' + extension):
			matches.append(os.path.join(root, filename))


	getFileStats(matches,extension)


def get_c_regex():
	ID = re.compile(r"[a-z]+\w*")
	NUMBER = re.compile(r"\-?([1-9]+[0-9]* | 0)")
	TYPE = re.compile(
		r"int | double | char | struct [a-z]+\w* | long | unsigned int | short | unsigned char | size_t | float | unsigned short | unsigned long")
	PTR = re.compile(r"(%s)\* | void\*"%(TYPE.pattern))
	VAR_TYPE = re.compile(r"(%s) | (%s)"%(TYPE.pattern,PTR.pattern))
	VAR_DEC = re.compile(r"(%s) (%s) | (%s) \*(%s)"%(VAR_TYPE.pattern,ID.pattern,TYPE.pattern,ID.pattern))

	NUM_OR_ID = re.compile(r"(%s) | (%s)"%(NUMBER.pattern,ID.pattern))
	ARRAY_DEC = re.compile(r"(%s)\[%s?\]"%(VAR_DEC.pattern,NUM_OR_ID.pattern))

	DEC = re.compile(r"(%s) | (%s)"%(VAR_DEC.pattern,ARRAY_DEC.pattern))

	VAR = re.compile(r"(%s) | (%s).(%s) | (%s)->(%s) | &(%s) | *(%s) | (%s)\[(%s)\]"%(
		ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,NUM_OR_ID.pattern))

	#function invocations
	FUNC_TYPE = re.compile(r"void | (%s)"%(VAR_TYPE.pattern))
	FUNC_INVOKE_NO_PARAMS = re.compile(r"(%s)\(\) | (%s) \*(%s)\(\)"%(VAR.pattern,TYPE.pattern,VAR.pattern))
	FUNC_INVOKE_WITH_PARAMS = re.compile(r"(%s)\((%s)+(,%s)*\) | (%s) \*(%s)\((%s)+(,%s)*\)"%(
		VAR.pattern,VAR_DEC.pattern,VAR_DEC.pattern,TYPE.pattern,VAR.pattern,VAR_DEC.pattern,VAR_DEC.pattern))
	FUNC_INVOKE = re.compile(r"(%s) | (%s)"%(FUNC_INVOKE_NO_PARAMS.pattern,FUNC_INVOKE_WITH_PARAMS.pattern))
	FUNC_DEF = re.compile(r"(%s) (%s)"%(FUNC_TYPE.pattern,FUNC_INVOKE.pattern));
	#operations
	BINOP = re.compile(r"[\+\-\*/%&\|\^]")
	LBINOP = re.compile(r"== | \|\| | && | > | <")
	NOT = re.compile(r"!(%s)"%(VAR.pattern))
	'''UOP = re.compile(r"(%s)\+\+ | \+\+(%s) | (%s)\-\- | \-\-(%s) | (%s) << (%s) | (%s) >> (%s)"%(
		VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern))'''

	#expressions
	BINEXP = re.compile(r"(%s) (%s) (%s) | (%s) (%s) (%s)"%(
		VAR.pattern,BINOP.pattern,VAR.pattern,VAR.pattern,LBINOP.pattern,VAR.pattern))
	CAST = re.compile(r"\((%s)\) (%s)"%(VAR_TYPE.pattern,VAR.pattern))
	#UEXP = re.compile(r"(%s) | (%s)"%(NOT.pattern,UOP.pattern))
	EXP = re.compile(r"(%s) | (%s) | NULL"%(BINEXP.pattern,NOT.pattern))

	#assign statements
	ASSIGN_EXP = re.compile(r"(%s) = (%s);"%(VAR.pattern,EXP.pattern))
	ASSIGN_VAR = re.compile(r"(%s) = (%s);"%(VAR.pattern,VAR.pattern))
	ASSIGN_FUNC_NO_PARAMS_RET_VAL = re.compile(r"(%s) = (%s);"%(VAR.pattern,FUNC_INVOKE_NO_PARAMS.pattern))
	ASSIGN_FUNC_WITH_PARAMS_RET_VAL = re.compile(r"(%s) = (%s);"%(VAR.pattern,FUNC_INVOKE_WITH_PARAMS.pattern))
	ASSIGN_INC_DEC = re.compile(r"(%s)\+\+ | \+\+(%s) | (%s)-- | --(%s)"%(VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern))
	ASSIGN_CAST = re.compile(r"(%s) = (%s)"%(VAR.pattern,CAST.pattern))

	#return statements
	RETURN = re.compile(r"return (%s); | return (%s); | return;"%(EXP.pattern,VAR.pattern))

	FUNC_INVOKE_STMT = re.compile(r"(%s);"%(FUNC_INVOKE.pattern))

	VAR_DEC_STMT = re.compile(r"(%s);"%(VAR_DEC.pattern))

	VAR_DEC_ASSIGN_STMT = re.compile(r"(%s) = (%s);"%(VAR_DEC.pattern,EXP.pattern))

	FUNC_DEF_STMT = re.compile(r"(%s);"%FUNC_DEF.pattern);

	'''STATEMENT = re.compile(r"(%s); | (%s); | (%s); | (%s); | (%s);"%(
		ASSIGN_EXP.pattern,RETURN,VAR_DEC.pattern,ARRAY_DEC.pattern,FUNC_INVOKE.pattern))'''

	IF = re.compile(r"if\((%s)\)"%(EXP.pattern))

	WHILE = re.compile(r"while\((%s)\)"%(EXP.pattern))
	'''FOR = re.compile(r"for\((%s)? ; (%s) ; (%s)\)"%(
		EXP.pattern,EXP.pattern,EXP.pattern))'''

	COMMENT = re.compile(r"\/\/\w* | \/\*\w*\/\*")

	GOTO = re.compile(r"goto (%s)"%(ID.pattern))

	return [ASSIGN_EXP,ASSIGN_VAR,ASSIGN_FUNC_WITH_PARAMS_RET_VAL,ASSIGN_FUNC_NO_PARAMS_RET_VAL,FUNC_INVOKE_STMT,RETURN,IF,\
	WHILE,VAR_DEC_STMT,VAR_DEC_ASSIGN_STMT,COMMENT,FUNC_DEF_STMT,ASSIGN_INC_DEC,ASSIGN_CAST,GOTO]


if __name__ == '__main__':
	C_REGEX = get_c_regex()
	score_dir_files('/','c')
	#380 correct out of 382 total (99.4764397906%) c files
	#824 correct out of 985 total (83.654822335%) txt files
	#825 correct out of 985 total (83.7563451777%)
