#!/usr/bin/python

import sys, getopt

def main():
	inputfile = ''
	outputfile = ''
	try:
		opts, args = getopt.getopt(argv,"hi:o: ",["ifile=", "ofile="])
	except getopt.GetoptError:
		print "autoDataCollect.py -i <input> -o <output>"
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print "autoDataCollect -i <input> -o <output>"
			sys.exit(1)
	    if opt == '-i':
			inputfile = arg
	    if opt == '-o':
			outputfile = arg

#	print 'input file is ', inputfile 
#	print 'output file is ', outputfile

if __name__ == "__main__":
	main()


#print "Hello, World!";
#raw_input("\n\nPress the enter key to exit..")
