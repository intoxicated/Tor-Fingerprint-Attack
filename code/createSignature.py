#!/usr/bin/python

from FingerprintAttackClasses import *
import sys, getopt, os

def Help():
		print "\nUsage: createSignature.py -d directory -w website options"
		print "\nOptions:" 
		print "\t-v version"
		print "\t-h help"
		print "\t-d directory to analyze"
		print "\t-b fingerprint database directory to store to"
		print "\t-n number of files to analyze in a folder before quitting"
		print "\t-w name of the website you are fingerprinting\n"
		sys.exit(1)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:],"vhd:b:n:w:")
	except getopt.GetoptError:
		print "We didn't recognize one of your otpions :("
		#usage()
		Help()
	for o,a in opts:
		if o == '-d':
			directory = a
		if o == '-b':
			dbDir = a
		if o == '-n':
			iters = int(a)
		if o == '-w':
			website = a
		if o == '-h':
			Help()
			sys.exit(1)
	# we must have a directory specified so if they don't exit
	try:
		directory
	except NameError:
		print "You must specify the directory you want to use.\n"
		sys.exit(1)

	try:
		website
	except NameError:
		website = directory.rstrip('/')
		website = website.split('/')[-1]
	multipleStreamsList = list()
	dirlist = os.listdir(directory)
	print "\nProcessing files from directory: " + directory + "\n"
	# process all pcap files in the given directory and put each stream 
	# into the multiple streams list
	for i in dirlist:
		try:
			iters
		except:
			iters = len(dirlist)
		if len(multipleStreamsList) < iters:
			print "Processing: " + directory + i
			plist = SimplePacketList()
			plist.loadFromPCAP(directory+i)
			
			sum_652 = 0
			for p in plist.packetList:
				if (p.SRC == '130.126.143.48' or p.SRC == '192.168.1.101')\
					and p.length > 600 and p.length < 700:
					sum_652 += 1	

			#print '\t%i' % (sum_652, )

			multipleStreamsList.append(plist)
	websiteFinger = WebsiteFingerprint()
	websiteFinger.loadFromStreamData(multipleStreamsList)
	try:
		dbDir
	except:
		dbDir = 0
	if dbDir:
		websiteFinger.writeToDB(website,dbDir)
	else:
		websiteFinger.writeToDB(website)

if __name__ == "__main__":
	main()
