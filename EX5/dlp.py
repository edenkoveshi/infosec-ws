#!/usr/bin/env python
import re
import fnmatch
import os
import string

def isCode(data):
	charsScoreAvg,lenAvg = getDataStats(data)
	score = getScore(charsScoreAvg,lenAvg)
	#print score
	return score > 0
	
def getScore(charsScoreAvg, lenAvg):
	"""
	Old Special is  2, 4.5, 7 for .c, 0, 0.5 ,3   for .txt
	    Length  is  0, 25, 36 for .c, 0, 180 ,360 for .txt
	    Normalize length by dividing it by 10.
	"""
	return charsScoreAvg-lenAvg/10	
	
def getDataStats(data):
	lines = data.split('\n')
	lines = filter(None,lines) #delete empty lines
	lines_amount = len(lines)
	lenSum = 0;
	charsScoreSum = 0;
	for line in lines:
		lenSum += len(line)
		charsScoreSum += charsAndWordsScore(line)
	
	return float(charsScoreSum)/lines_amount,float(lenSum)/lines_amount

def charsAndWordsScore(line):
	double_score_chars = ['{','}','=','<','>','+','#','*']
	high_conf = ["#include ",".h>",".h\"","#if ","#endif","NULL","0x"]
	low_conf  = ["extern ","const ","struct ","static ","void ","if","else","return ","int ","char ","long ","double ","float ","case "]
	score = 0
	for match in re.findall(r'[{}()#\\/*+\-=<>_;]{1}', line):
		if match in double_score_chars:
			score += 5
		else:
			score += 1
	for match in re.findall('|'.join(high_conf), line, flags=re.IGNORECASE):
			score += 20
	for match in re.findall('|'.join(low_conf), line, flags=re.IGNORECASE):
			score += 1
			
	if line[len(line)-1] == ';':
		score += 5
	if line[len(line)-1] == '.':
		score -= 1
	if line[0] in string.ascii_uppercase:
		score -= 1
	

	score += len(re.findall(r'[0-9]+[,]{1}', line)) #comma seperated numbers	
	return score
	
def getFileStats(filenames):
	linesSum, lenAvgSum, specialAvgSum = 0,0,0
	for filename in filenames:
		charsScoreAvg,lenAvg = getDataStats(open(filename,'r').read())
		print getScore(charsScoreAvg,lenAvg)
		"""if (getDataStats(open(filename,'r').read()) > 0):
			os.system('geany {}&'.format(filename))
			print filename"""

def score_dir_files(path,extension):
	matches = []
	for root, dirnames, filenames in os.walk(path):
		for filename in fnmatch.filter(filenames, '*.' + extension):
			matches.append(os.path.join(root, filename))


	getFileStats(matches)
	

#score_dir_files('/media/linuxsrc/','c')
#score_dir_files('/home/fw/Desktop/redis/src','c')
#score_dir_files('/home/fw/Desktop/bbc','txt')
