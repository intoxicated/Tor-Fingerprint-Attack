#!/usr/bin/python

import  sys, os, math, getopt, time, operator, ConfigParser
#from pygame.locals import *
from decimal import *
from pyx import *


text.set(mode="latex")

version=0.9

Analyze=1
Graph=0
GraphCharLimit=30
PrintOut=0
Quiet=0
filename=""
pdfFilename="out.pdf"
Pcap=""


def Help():
		print "data.py -f filename options"
		print "Options:" 
		print "          -v version"
		print "          -h help"
		print "          -f filename to analyze"
		print "          -a full Analyze"
		print "           do all calculations"
		print "          -g graph to file"
		print "           make a chart graph to file. default: out.pdf"
		print "          -p print"
		print "           prints out everything"
		print "          -q quiet"
		print "           only say what is required"
		print "          -r reductionlimit"
		print "           redacts char limit if len(k)>char"
		print "Note: currently -a is assumed."
		sys.exit(1)

def SortDictValues(adict):
	return sorted(adict.iteritems(),key=operator.itemgetter(1))

def GraphOnScreen(myList, numberofTop):
	return 0

#def handle_pack(sec, usec, pkt, headers):
#	print "%s:%d %s:%d (%d bytes)" % (headers['ip']['srcAddr'], headers['udp']['srcPort'],headers['ip']['dstAddr'], headers['udp']['dstPort'],len(pkt))
#	print pcaputils.hexdump(pkt)


try:
	opts, args = getopt.getopt(sys.argv[1:],"cvhqagpf:r:")
except getopt.GetoptError:
	print "We didn't recognize one of your otpions :("
	Help()

for o,a in opts:#O(n^2) :(
	if   o == "-h":
		Help()
	elif o == "-c":
		try:
			os.rmdir('graph')
			os.rmdir('tmp')
		finally:
			sys.exit(1)
	elif o == "-v":
		print version
		sys.exit(1)
	elif o == "-p":
		PrintOut=1
	elif o == "-a":
		Analyze = 1
	elif o == "-g":
		if a!="":
			pdfFilename=a
		else:
			pdfFilename="out"
		Graph = 1
	elif o == "-f":
		filename = a
	elif o == "-q":
		Quiet=1
	elif o == '-r':
		GraphCharLimit = a
#	elif o == '-u':
#		Pcapfile= a

if filename=="": #1 = data.py 2= file name
	print "-f filename is mandatory"
	print "Do data.py -h for help"
	sys.exit(1)

#if(Pcapfile !=""):
#	p=pcaputils.pcaputils(Pcapfile)
#	p.subscribe("1", handle_pack)
#	sys.exit(1)



try:
	f=open(filename,'r')
except IOError:
	print "Unable to open file you requested"
	print "You requested: " + filename
	sys.exit(1)

config = ConfigParser.RawConfigParser()
config.read('entry.cfg')

STRTVAL=config.getint('Section1','START')
ENDVAL =config.getint('Section1','END') +1 
GRAPHNAME=list()
for i in range(STRTVAL,ENDVAL,1):
	GRAPHNAME.append(config.get('Section1','NAME'+str(i)))
splCharInt=config.getint('Section1','SPLITCHAR')

if(splCharInt==0):
	SPLITCHAR=','
elif (splCharInt==1):
	SPLITCHAR=''

lineNumber=0

myOriginalList=list() #list of tuples

if Quiet ==0:
	print "Beggining Reading into Memory"

for line in f:
	lineNumber+=1
	line=line.replace('"','')
	line=line.replace('\n','')
	if(SPLITCHAR==''):
		arr=line.split()
	else:
		arr=line.split(SPLITCHAR)
	try:
		myOriginalList.append(tuple(arr[STRTVAL:ENDVAL]))
	except:
		print "Invalid Entry spotted at line..."+ str(lineNumber)

f.close()
if Quiet ==0:
	print "Completed Reading into Memory"

anDict = list() # LIST OF DICTS

for num in range(STRTVAL,ENDVAL,1):
	anDict.append(dict())

if Analyze == 1:
	if Quiet==0:
		print "Running full blown analysis..."
	for myLineTuple in myOriginalList:
		for dictNumber in range(0,ENDVAL-STRTVAL,1):
			if myLineTuple[dictNumber] in anDict[dictNumber]:
				anDict[dictNumber][myLineTuple[dictNumber]]+=1
			else:
				anDict[dictNumber][myLineTuple[dictNumber]]=1

if(os.path.isdir("tmp")==0):
	os.mkdir('tmp')
if(os.path.isdir('graph')==0):
	os.mkdir('graph')

if PrintOut == 1:
	for dictNumber in range(0,ENDVAL-STRTVAL,1):
		print "==========Printing Tuple",dictNumber
#		for k,v in anDict[dictNumber].iteritems():
#			print k,':',v
		for k,v in SortDictValues(anDict[dictNumber]):
			print k,':',v

#This uses different files due to cache
if Graph:
	space=1
	for dictNumber in range(0,ENDVAL-STRTVAL,1)[0:]:
		f=open('tmp/tmp'+str(dictNumber)+'.dat','w')
		for k,v in SortDictValues(anDict[dictNumber]):
			if(len(k)>GraphCharLimit):
				k="etc"
			f.write(str(k).replace('_',' ')+' '+str(v)+' '+'\n')
		f.close()
		mypainter = graph.axis.painter.bar(nameattrs=[trafo.rotate(60),text.halign.right],innerticklength=0.25)
		myaxis =graph.axis.bar(painter=mypainter,title=GRAPHNAME[dictNumber])
		g = graph.graphxy(width=8,x=myaxis)
		g.plot(graph.data.file('tmp/tmp'+str(dictNumber)+'.dat',xname=1,y=2), [graph.style.bar()])
		g.writePDFfile('graph/'+pdfFilename+str(dictNumber))
		
	

#if Graph:
#	pygame.init()
#	windows = pygame.display.set_mode((SizeX,SizeY))
#	pygame.display.set_caption("Data Analyze")
#	screen = pygame.display.get_surface()

#	while 1:
#		screen.fill((0,0,0))
#		time.sleep(0.0001)
#		for event in pygame.event.get():
#			if event.type == pygame.QUIT:
#				sys.exit()
if Quiet ==0:
	print "Done with everything you asked me to do!"
