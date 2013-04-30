#!/usr/bin/python

from FingerprintAttackClasses import *
import sys, getopt, os

def Help():
		print "\ntorfa.py -f 'path to mobius data file' options"
		print "\nOptions:" 
		print "\t-v version"
		print "\t-h help"
		print "\t-f data file to analyze"
		print "\t-d fingerprint database dir: defaults to ./KnownFingerprints \n"
		sys.exit(1)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:],"vhf:d:")
	except getopt.GetoptError:
		print "We didn't recognize one of your otpions :("
		#usage()
		Help()
	for o,a in opts:
		if o == '-f':
			datafile = a
		if o == '-d':
			dbDir = a
		if o == '-h':
			Help()
			exit(1)
	# we must have a pcap file specified so if they don't we exit
	try:
		datafile
	except NameError:
		print "You must specify the pcap file you want to use.\n"
		sys.exit(1)

	# if they gave a db directory then we use it, if not we set it to
	# a default based on current dir
	try:
		dbDir
	except NameError:
		dbDir = "KnownFingerprints"

	# to make to loading function in the fingerprint class we need to put
	# this packet list into a stream so that it parses right. It should 
	# be fixed so we can just add a single packet list
	unknownFingerprint = WebsiteFingerprint()
	unknownFingerprint.loadFromDB(datafile)

	# now compare the individual streams verses all fingerprints in the
	# db to see if there is a match
	fingerprintList = os.listdir(dbDir)
	for i in fingerprintList:
		print "Comparing Fingerprint: " + i
		websiteFinger = WebsiteFingerprint()
		websiteFinger.loadFromDB(dbDir+"/"+i)
		res = unknownFingerprint.getKLDivergence(websiteFinger)
		for val in res:
			print "\t\tKL-Divergence is: %f" % (val, )
	# now we print results

if __name__ == "__main__":
	main()
