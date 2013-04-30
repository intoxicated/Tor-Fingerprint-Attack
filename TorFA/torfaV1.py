#!/usr/bin/python
#Finger print attack 
#This class is to compare given file/folder
#with Knownfingerprint by using KL-D and Variance
#
# branch V1
# modified 1/29/10
# by realfree

from FingerprintAttackClasses import *
import sys, getopt, os

def Help():
		print "\ntorfa.py -f pcapfile options"
		print "\nOptions:" 
		print "\t-v version"
		print "\t-h help"
		print "\t-f folder name contains pcap files to analyze"
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
			tdbDir = a
		if o == '-d':
			dbDir = a
		if o == '-h':
			Help()
			exit(1)
	# we must have a pcap file specified so if they don't we exit
#	try:
#		pcapfile
#	except NameError:
#		print "You must specify the pcap file you want to use."
#		sys.exit(1)
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
	
	# unless 
	try:
		tdbDir
	except NameError:
		tdbDir = "./dataCollection" 

	resultList = open('resultlist.txt', 'w')	
	for expertType in os.listdir(tdbDir):
		#expertNum = 0
		expertSuccess = 0
		expertFailure = 0
		for website in os.listdir(tdbDir+'/'+expertType):
			successDiv = 0
			successVar = 0
			failureDiv = 0
			failureVar = 0
			for pFile in os.listdir(tdbDir+'/'+expertType+'/'+website):	
				# first we read in data from the pcap file and put it into a packetlist
				pList = SimplePacketList()
				pList.loadFromPCAP(tdbDir+'/'+expertType+'/'+website+'/'+pFile)
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
			#	filehan = open(resultsFile,'w')
			#	filehan.write('Comparing Results for %s\n'%(tdbDir+'/'+expertType+'/'+website+'/'+pFile))
			#	filehan.write('Total Packets: %f\n' % (unknownFingerprint.probVectSet[0].packetCountMean,))
			#	filehan.write('Fingerprint,KL-Divergence,Number of Packets,' + \
			#	'Total Packet Deviation,Standard Deviation Match, Variance Match\n')
				matchesDiv = []
				matchesVariance = []
				for i in fingerprintList:
			#		print "\nComparing Fingerprint: " + i
					websiteFinger = WebsiteFingerprint()
					websiteFinger.loadFromDB(dbDir+"/"+i)
					#for x in websiteFinger.probVectSet:
					#	x.printme()
					kldiv = unknownFingerprint.getKLDivergence(websiteFinger)
					for val in kldiv:
		#				print "\tKL-Divergence is: %f" % (val, )
					packDev = abs(websiteFinger.probVectSet[0].packetCountMean-unknownFingerprint.probVectSet[0].packetCountMean)
					if packDev < 3*websiteFinger.probVectSet[0].stddev:
		#				inDev = 'yes'
						matchesDiv.append([i,kldiv[0]])
		#			else:
		#				inDev = 'no'
					if packDev < websiteFinger.probVectSet[0].variance:
		#				inVar = 'yes'
						matchesVariance.append([i,kldiv[0]])
		#			else:
		#				inVar = 'no'
		#			string = '%s,\t%f,\t%f,\t%f,\t%s,\t%s\n\n' % (i,kldiv[0], \
		#				websiteFinger.probVectSet[0].packetCountMean,packDev,inDev,inVar)
		#			filehan.write(string) 
							
				matchNameDiv = 'none'
				matchKLDDiv = 1000
				for ma in matchesDiv:
					if ma[1] < matchKLDDiv:
						matchNameDiv = ma[0]
						matchKLDDiv = ma[1]
		#		print '\n\nThe website from deviation matching is: %s with KL-Divergence: %f\n' % (matchNameDiv,matchKLDDiv)
		#		if expertType != 'Experiment3':
				if matchNameDiv == website:
					successDiv += 1
				elif matchNameDiv != website:
					failureDiv += 1
		#		print '\n\t\t\t\t\%d , %d'%(successDiv, failureDiv)
				
				matchNameVar = 'none'
				matchKLDVar = 1000
				for ma in matchesVariance:
					if ma[1] < matchKLDVar:
						matchNameVar = ma[0]
						matchKLDVar = ma[1]
		#		if expertType != 'Experiment3':
				if matchNameVar == website:
					successVar += 1
				elif matchNameVar != website:
					failureVar += 1
		#		print '\n\t\t\t\t\%d , %d'%(successVar, failureVar)
		#		print '\n\nThe website from deviation matching is: %s with KL-Divergence: %f\n' % (matchNameVar,matchKLDVar)

		#if expertType != 'Experiment3':
			percentSuccess = (successDiv*100) / (successDiv+failureDiv)
			percentFailure = 100 - percentSuccess 
			resultDiv =  '\n\nThe website %s sucess match: %f(%d),\t\t fail: %f(%d), by Div\n' % (website, percentSuccess, successDiv, percentFailure, failureDiv)
			percentSuccess = (successVar*100) / (successVar+failureVar)
			percentFailure = 100 - percentSuccess
			resultVar = '\n\nThe website %s sucess match : %f(%d), \t\t fail: %f(%d), by Var\n' % (website, percentSuccess, successVar, percentFailure, failureVar)
			resultList.write(resultDiv)
			resultList.write(resultVar)
		#	print 'The website %s sucess match: %d, fail: %d, total : %d Var\n' % (website, successVar, failureVar) 		
			#one website done, go on
		#print 'The %s overall matching is %f \n' % (expertType, expertSuccess/(expertSucess+expertFailure))
		#now done one experimentation mark up and go on


	# now we print results

if __name__ == "__main__":
	main()
