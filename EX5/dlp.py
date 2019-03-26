#!/usr/bin/env python
import re
import fnmatch
import os
import string

C_REGEX = []

def isCode(data):
	data_avg_score,data_avg_line_length = get_data_score(data)
	if(data_avg_score < 0): #almost no chance to enter this,but either way this is a text file
		return False
	score = (float)((data_avg_score + 1)/(data_avg_line_length + 1))
	return score > 1
	
def get_data_score(data):
	lines = data.split('\n')
	lines = list(filter(lambda x: x!=None,lines)) #delete empty lines
	num_lines = len(lines)
	lines_len_sum = 0;
	lines_score_sum = 0;
	for line in lines:
		lines_len_sum += len(line)
		lines_score_sum += get_line_score(line)
	
	return float(lines_score_sum)/num_lines,float(lines_len_sum)/num_lines 

def get_line_score(line):
	double_score_chars = ['{','}','=','<','>','+','#','*']
	high_conf = ["#include ",".h>",".h\"","#if ","#endif","NULL","0x","->","malloc","stdlib"]
	low_conf  = ["extern ","const ","struct ","static ","void ","if","else","return ","int ","char ","long ","double ","float ","case "]
	score = 0

	for exp in C_REGEX:
		matches = re.findall(exp,line)
		r = re.findall(r'[{}()#\\/*+\-=<>_;]{1}', line)
		for match in matches:
			score += 30
		for match in r:
			if(match in double_score_chars and match not in matches):
				score += 5
			else:
				score += 1
		for match in re.findall('|'.join(high_conf), line, flags=re.IGNORECASE):
				score += 20
		for match in re.findall('|'.join(low_conf), line, flags=re.IGNORECASE):
				score += 1

	if(line[-1:] not in [';','{','}']): #c files are more likely to end with these
		score -= 1
				
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
		r"int | double | char | struct %s | long | unsigned int | short | unsigned short | unsigned char | size_t"%(
			ID.pattern))
	PTR = re.compile(r"(%s)\* | void\*"%(TYPE.pattern))
	VAR_TYPE = re.compile(r"(%s) | (%s)"%(TYPE.pattern,PTR.pattern))
	VAR_DEC = re.compile(r"(%s) (%s) | (%s) \*(%s)"%(VAR_TYPE.pattern,ID.pattern,TYPE.pattern,ID.pattern))

	NUM_OR_ID = re.compile(r"(%s) | (%s)"%(NUMBER.pattern,ID.pattern))
	ARRAY_DEC = re.compile(r"(%s)\[%s\]"%(VAR_DEC.pattern,NUM_OR_ID.pattern))

	VAR = re.compile(r"(%s) | (%s).(%s) | (%s)->(%s) | &(%s) | *(%s) | (%s)\[(%s)\]"%(
		ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,ID.pattern,NUM_OR_ID.pattern))

	#function invocations
	FUNC_TYPE = re.compile(r"void | (%s)"%(VAR_TYPE.pattern))
	FUNC_INVOKE_NO_PARAMS = re.compile(r"(%s) (%s)\(\) | (%s) \*(%s)\(\)"%(FUNC_TYPE.pattern,VAR,TYPE.pattern,VAR.pattern))
	FUNC_INVOKE_WITH_PARAMS = re.compile(r"(%s) (%s)\((%s)+(,%s)*\) | (%s) \*(%s)\((%s)+(,%s)*\)"%(
		FUNC_TYPE.pattern,VAR.pattern,VAR_DEC.pattern,VAR_DEC.pattern,TYPE.pattern,VAR.pattern,VAR_DEC.pattern,VAR_DEC.pattern))
	FUNC_INVOKE = re.compile(r"(%s) | (%s)"%(FUNC_INVOKE_NO_PARAMS.pattern,FUNC_INVOKE_WITH_PARAMS.pattern))

	#operations
	BINOP = re.compile(r"[\+\-\*/%&\|\^]")
	LBINOP = re.compile(r"== | \|\| | && | > | <")
	NOT = re.compile(r"!(%s)"%(VAR.pattern))
	'''UOP = re.compile(r"(%s)\+\+ | \+\+(%s) | (%s)\-\- | \-\-(%s) | (%s) << (%s) | (%s) >> (%s)"%(
		VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern,VAR.pattern))'''

	#expressions
	BINEXP = re.compile(r"(%s) (%s) (%s) | (%s) (%s) (%s)"%(
		VAR.pattern,BINOP.pattern,VAR.pattern,VAR.pattern,LBINOP.pattern,VAR.pattern))
	#UEXP = re.compile(r"(%s) | (%s)"%(NOT.pattern,UOP.pattern))
	EXP = re.compile(r"(%s) | (%s) | NULL"%(BINEXP.pattern,NOT.pattern))

	#assign statements
	ASSIGN_EXP = re.compile(r"(%s) = (%s);"%(VAR.pattern,EXP.pattern))
	ASSIGN_VAR = re.compile(r"(%s) = (%s);"%(VAR.pattern,VAR.pattern))
	ASSIGN_FUNC_NO_PARAMS_RET_VAL = re.compile(r"(%s) = (%s);"%(VAR.pattern,FUNC_INVOKE_NO_PARAMS.pattern))
	ASSIGN_FUNC_WITH_PARAMS_RET_VAL = re.compile(r"(%s) = (%s);"%(VAR.pattern,FUNC_INVOKE_WITH_PARAMS.pattern))

	#return statements
	RETURN = re.compile(r"return (%s); | return (%s); | return;"%(EXP.pattern,VAR.pattern))

	FUNC_INVOKE_STMT = re.compile(r"(%s);"%(FUNC_INVOKE.pattern))

	VAR_DEC_STMT = re.compile(r"(%s);"%(VAR_DEC.pattern))

	VAR_DEC_ASSIGN_STMT = re.compile(r"(%s) = (%s);"%(VAR_DEC.pattern,EXP.pattern))

	'''STATEMENT = re.compile(r"(%s); | (%s); | (%s); | (%s); | (%s);"%(
		ASSIGN_EXP.pattern,RETURN,VAR_DEC.pattern,ARRAY_DEC.pattern,FUNC_INVOKE.pattern))'''

	IF = re.compile(r"if\((%s)\)"%(EXP.pattern))

	WHILE = re.compile(r"while\((%s)\)"%(EXP.pattern))
	'''FOR = re.compile(r"for\((%s)? ; (%s) ; (%s)\)"%(
		EXP.pattern,EXP.pattern,EXP.pattern))'''

	COMMENT = re.compile(r"\/\/\w* | \/\*\w*\/\*")

	return [ASSIGN_EXP,ASSIGN_VAR,ASSIGN_FUNC_WITH_PARAMS_RET_VAL,ASSIGN_FUNC_NO_PARAMS_RET_VAL,FUNC_INVOKE_STMT,RETURN,IF,\
	WHILE,VAR_DEC_STMT,VAR_DEC_ASSIGN_STMT,COMMENT]


if __name__ == '__main__':
	C_REGEX = get_c_regex()
	score_dir_files('/','txt')
	#380 correct out of 382 total (99.4764397906%) c files
	#824 correct out of 985 total (83.654822335%) txt files
	#825 correct out of 985 total (83.7563451777%)
