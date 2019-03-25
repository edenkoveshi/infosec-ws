#!/usr/bin/env python
import re
import fnmatch
import os
import string

def isCode(data):
	data_avg_score,data_avg_line_length = get_data_score(data)
	score = data_avg_score-data_avg_line_length/10
	return score > 0
	
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
	high_conf = ["#include ",".h>",".h\"","#if ","#endif","NULL","0x",'\{','\}','=','<','>','\+','#','\*',"stdlib","->"]
	low_conf  = ["extern ","const ","struct ","static ","void ","if","else","return ","int ","char ","long ","double ","float ","case "]
	regex = get_c_regex()
	#regex = get_minimal_c_regex()
	score = 0
	for match in re.findall(r'[{}()#\\/*+\-=<>_;]{1}', line):
		if match in high_conf:
			score += 5
		else:
			score += 1
	for exp in regex:
		matches = re.findall(exp,line)
		for match in matches:
			score += 30	
		for match in re.findall('|'.join(high_conf), line, flags=re.IGNORECASE): #join many high confidence words
			if(match not in matches):
				score += 15
		for match in re.findall('|'.join(low_conf), line, flags=re.IGNORECASE): #join many low confidence words
			if(match not in matches):
				score += 3
				
		'''if line[-1:] == ';': #end of line is ; - typical to C code
			score += 5
		if line[-1:] == '.': #end of line is . - typical to text files
			score -= 1
		if line[0] in string.ascii_uppercase: #line begins with uppercase letter - typical to text files
			score -= 1'''
	

	#score += len(re.findall(r'[0-9]+[,]{1}', line)) #comma seperated numbers	
	return score
	
def getFileStats(filenames):
	linesSum, lenAvgSum, specialAvgSum = 0,0,0
	for filename in filenames:
		print isCode((open(filename,'r').read()))
		#print get_line_score(charsScoreAvg,lenAvg)
		"""if (getDataStats(open(filename,'r').read()) > 0):
			os.system('geany {}&'.format(filename))
			print filename"""

def score_dir_files(path,extension):
	matches = []
	for root, dirnames, filenames in os.walk(path):
		for filename in fnmatch.filter(filenames, '*.' + extension):
			matches.append(os.path.join(root, filename))


	getFileStats(matches)


def get_c_regex():
	ID = re.compile(r"[a-z]+\w*")
	NUMBER = re.compile(r"\-?([1-9]+[0-9]* | 0)")
	TYPE = re.compile(r"int | double | char | struct %s"%(ID.pattern))
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

	return [ASSIGN_EXP,ASSIGN_VAR,ASSIGN_FUNC_WITH_PARAMS_RET_VAL,ASSIGN_FUNC_NO_PARAMS_RET_VAL,FUNC_INVOKE_STMT,RETURN,IF,\
	WHILE,VAR_DEC_STMT,VAR_DEC_ASSIGN_STMT]


#if __name__ == '__main__':
	#score_dir_files('/home/fw/github/infosec-ws','c')
