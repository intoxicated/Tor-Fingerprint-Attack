#!/usr/bin/python

from FingerprintAttackClasses import *
import sys, getopt, os

def Help():
		print "\ntorfa.py -f pcapfile options"
		print "\nOptions:" 
		print "\t-v version"
		print "\t-h help"
		print "\t-f pcap file to analyze"
		print "\t-d fingerprint database dir: defaults to ./KnownFingerprints \n"
		sys.exit(1)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:],"vhf:d:r:")
	except getopt.GetoptError:
		print "We didn't recognize one of your otpions :("
		#usage()
		Help()
	for o,a in opts:
		if o == '-r':
			resultsFile = a
		if o == '-f':
			pcapfile = a
		if o == '-d':
			dbDir = a
		if o == '-h':
			Help()
			exit(1)
	# we must have a pcap file specified so if they don't we exit
	try:
		pcapfile
	except NameError:
		print "You must specify the pcap file you want to use.\n"
		sys.exit(1)
	try: 
		resultsFile
	except:
		print "You forgot results file\n"
		sys.exit(1)

	# if they gave a db directory then we use it, if not we set it to
	# a default based on current dir
	try:
		dbDir
	except NameError:
		dbDir = "KnownFingerprints"

	# first we read in data from the pcap file and put it into a packetlist
	pList = SimplePacketList()
	pList.loadFromPCAP(pcapfile)
	# to make to loading function in the fingerprint class we need to put
	# this packet list into a stream so that it parses right. It should 
	# be fixed so we can just add a single packet list
	streamList = [pList]

	# Create fingerprint from streams list
	unknownFingerprint = WebsiteFingerprint()
	unknownFingerprint.loadFromStreamData(streamList)

	# now compare the individual streams verses all fingerprints in the
	# db to see if there is a match
	fingerprintList = os.listdir(dbDir)
	filehan = open(resultsFile,'w')
	filehan.write('Comparing Results for %s\n'%(pcapfile))
	filehan.write('Total Packets: %f\n' % (unknownFingerprint.probVectSet[0].packetCountMean,))
	filehan.write('Fingerprint,KL-Divergence,Number of Packets,' + \
		'Total Packet Deviation,Standard Deviation Match, Variance Match\n')
	matchesDiv = []
	matchesVariance = []
	for i in fingerprintList:
		print "\nComparing Fingerprint: " + i
		websiteFinger = WebsiteFingerprint()
		websiteFinger.loadFromDB(dbDir+"/"+i)
		#for x in websiteFinger.probVectSet:
		#	x.printme()
		kldiv = unknownFingerprint.getKLDivergence(websiteFinger)
		for val in kldiv:
			print "\tKL-Divergence is: %f" % (val, )
		packDev = abs(websiteFinger.probVectSet[0].packetCountMean - \
			unknownFingerprint.probVectSet[0].packetCountMean)
		if packDev < 3*websiteFinger.probVectSet[0].stddev:
			inDev = 'yes'
			matchesDiv.append([i,kldiv[0]])
		else:
			inDev = 'no'
		if packDev < websiteFinger.probVectSet[0].variance:
			inVar = 'yes'
			matchesVariance.append([i,kldiv[0]])
		else:
			inVar = 'no'
		string = '%s,%f,%f,%f,%s,%s\n' % (i,kldiv[0], \
			websiteFinger.probVectSet[0].packetCountMean,packDev,inDev,inVar)
		filehan.write(string) 

	matchNameDiv = 'none'
	matchKLDDiv = 1000
	for ma in matchesDiv:
		if ma[1] < matchKLDDiv:
			matchNameDiv = ma[0]
			matchKLDDiv = ma[1]
	print '\n\nThe website from deviation matching is: %s with KL-Divergence: %f\n' % (matchNameDiv,matchKLDDiv)
	
	matchNameVar = 'none'
	matchKLDVar = 1000
	for ma in matchesVariance:
		if ma[1] < matchKLDVar:
			matchNameVar = ma[0]
			matchKLDVar = ma[1]

	print '\n\nThe website from variance matching is: %s with KL-Varergence: %f\n' % (matchNameVar,matchKLDVar)




	# now we print results

if __name__ == "__main__":
	main()
