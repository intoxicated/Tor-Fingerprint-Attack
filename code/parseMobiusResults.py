#!/usr/bin/python

from FingerprintAttackClasses import *
import sys, getopt, os, re

from mpl_toolkits.mplot3d import Axes3D
from matplotlib import cm
import matplotlib.pyplot as plt
import numpy as np
import Gnuplot


def Help():
		print "\nUsage: createSignature.py -f 'mobius results file' -w website options"
		print "\nOptions:" 
		print "\t-v version"
		print "\t-h help"
		print "\t-f results file to analyze"
		print "\t-d db directory defaults to ./Knownfingerprints"
		print "\t-o output file to write results data to"
		print "\t-t type of simulation: constant or varied"
		sys.exit(1)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:],"vhf:d:o:t:")
	except getopt.GetoptError:
		print "We didn't recognize one of your otpions :("
		#usage()
		Help()
	for o,a in opts:
		if o == '-f':
			mobiusResultsFile = a
		if o == '-o':
			outputFile = a
		if o == '-t':
			type = a
		if o == '-h':
			Help()
			sys.exit(1)
	# we must have a directory specified so if they don't exit
	try:
		mobiusResultsFile
	except NameError:
		print "You must specify the directory you want to use.\n"
		sys.exit(1)
	try:
		dbDir
	except NameError:
		dbDir = "KnownFingerprints"
	try:
		type
	except NameError:
		print "You must specify an mobius simulation type"
		sys.exit(1)
	try:
		outputFile
	except NameError:
		if type == 'constant':
			outputFile = 'constant_plot.data'
		else:
			outputFile = 'varied_plot.data'
	# Experiment 1,double,addPacketProb,0.0
	# Experiment 1,double,dropPacketProb,0.0
	# Experiment 1,Mean,range4,10.0,10.0,5.5000000000E01 ,+/-,2.9554673261E-08
	# Experiment 1,Mean,tpacks,0.0,0.0,0.0000000000E00 ,+/-,0.0000000000E00

	resultsFileHandle = open(mobiusResultsFile,'r')

	experiment = 1
	addpre = 'asdlfj'
	droppre = 'a;lsdfjas'
	range1re = 'asdl;fj' 
	range2re = 'asdl;fj'
	range3re = 'asdl;fj'
	range4re = 'asdl;fj'
	tpacksre = 'as;dflkj'
	eps = .1
	finishTime = 0.0
	currentTime = 0.0
	lastTime = 0.0
	prevPackets = 0.0
	currentPackets = 0.0
	addpercent = 0
	droppercent = 0
	count = 0 
	probVect1 = ProbDistribution('prv1',4)

	arate = np.arange(0, .325, 0.025)
	drate = np.arange(0, .325, 0.025)
	X = np.arange(0, .325, 0.025)
	Y = np.arange(0, .325, 0.025)
	Xm, Ym = np.meshgrid(X, Y)

	exp1Data = {'divergence' : 0, 'totalPackets' : 0, 'finishTime' : 0}

	graphDataDivergence = []
	graphDataTime = []
	graphDataTotalPackets = []
	graphDataPercDivergence = []
	graphDataPercTime = []
	graphDataPercTotalPackets = []
	graphDataPercDiff = []
	
	if type == 'varied':
		addpack = 'maxAdd'
		droppack = 'maxDrop'
	else:
		addpack = 'addPacketProb'
		droppack = 'dropPacketProb'

	# Here we go through each line of the file. We match at certain points
	# to denote that we have found a given line that we are looking for.
	# When we have matched the fourth range value then we have matched all
	# important information from that single experiment and now do some
	# work on it. 
	for line in resultsFileHandle.readlines():
		line = line.rstrip()
		if line == 'Experiment ' + str(experiment):
			print '\n' + line 
			addpre = 'Experiment %i,double,%s,' % (experiment,addpack)
		if re.match(addpre,line):
			print '\tAdd Probability: ' + line.split(',')[3]
			addprob = float(line.split(',')[3])
			droppre = 'Experiment %i,double,%s,' % (experiment,droppack)
		if re.match(droppre,line):
			print '\tDrop Probability: ' + line.split(',')[3]
			dropprob = float(line.split(',')[3])
			tpacksre = 'Experiment %i,Mean,tpacks' % (experiment,)
		if re.match(tpacksre,line):
			currentTime = float(line.split(',')[3])
			currentPackets = float(line.split(',')[5])
			if (currentPackets - prevPackets) < eps:
				finishTime = lastTime
			else:
				lastTime = currentTime
				prevPackets = currentPackets
			range1re = 'Experiment %i,Mean,range1,' % (experiment,)
		if re.match(range1re,line):
			print '\tRange 1 Count: ' + str(float(line.split(',')[5]))
			probVect1.countVector[0] = float(line.split(',')[5])
			range2re = 'Experiment %i,Mean,range2,' % (experiment,)
		if re.match(range2re,line):
			print '\tRange 2 Count: ' + str(float(line.split(',')[5]))
			probVect1.countVector[1] = float(line.split(',')[5])
			range3re = 'Experiment %i,Mean,range3,' % (experiment,)
		if re.match(range3re,line):
			print '\tRange 3 Count: ' + str(float(line.split(',')[5]))
			probVect1.countVector[2] = float(line.split(',')[5])
			range4re = 'Experiment %i,Mean,range4,' % (experiment,)
		if re.match(range4re,line):
			print '\tRange 4 Count: ' + str(float(line.split(',')[5]))
			probVect1.countVector[3] = float(line.split(',')[5])
			probVect1.fillProbVector()
			#probVect1.printme()
			print "\tFinish time: " + str(finishTime)
			unknownFingerprint = WebsiteFingerprint()
			unknownFingerprint.addProbVector(probVect1)
			# now compare the individual streams verses all fingerprints in the
			# db to see if there is a match
			fingerprintList = os.listdir(dbDir)
			print "\n\tComparing fingerprint to calculate divergence"
			for i in fingerprintList:
				websiteFinger = WebsiteFingerprint()
				websiteFinger.loadFromDB(dbDir+"/"+i)
				res = unknownFingerprint.getKLDivergence(websiteFinger)
				if i == 'tsquare':
					divergence = res[0]
				for val in res:
					print "\t %-20s==> %2s KL-Divergence is: %10f" % (i,'',val)
			if experiment == 1:
				exp1Data['divergence'] = divergence
				exp1Data['finishTime'] = finishTime
				exp1Data['totalPackets'] = currentPackets
				print exp1Data
				sys.stdin.read(1)
			if finishTime != 0:
				graphDataDivergence.append((addprob,dropprob,divergence))	
				graphDataTime.append((addprob,dropprob,finishTime))
				graphDataTotalPackets.append((addprob,dropprob,currentPackets))
				graphDataPercDivergence.append((addprob,dropprob,
					divergence*100/exp1Data['divergence']))	
				graphDataPercTime.append((addprob,dropprob,
					finishTime*100/exp1Data['finishTime']))
				graphDataPercTotalPackets.append((addprob,dropprob,
					currentPackets*100/exp1Data['totalPackets']))
			# Reset vars for next time through
			prevPackets = 0.0
			lastTime = 0.0
			experiment+=1
	
	write3DPlotData(graphDataDivergence, './plots/divergence_'+outputFile)
	write3DPlotData(graphDataTime,'./plots/time_'+outputFile)
	write3DPlotData(graphDataTotalPackets,'./plots/totalPackets_'+outputFile)
	write3DPlotData(graphDataPercDivergence, './plots/divergence_perc_'+outputFile)
	write3DPlotData(graphDataPercTime,'./plots/time_perc_'+outputFile)
	write3DPlotData(graphDataPercTotalPackets,'./plots/totalPackets_perc_'+outputFile)
	
	
	graphDataPercDiff.append(graphDataPercDivergence)
	graphDataPercDiff.append(graphDataPercTotalPackets)
	graphDataPercDiff.append(graphDataPercTime)

	#write2DClusterBarData(graphDataPercDiff,'./plots/2d_perc_dif_'+outputFile)
	
	#gp = Gnuplot.Gnuplot(persist = 1)
	#gp('set data style lines')
	#gp('set surface')
	#gp('set isosamples 31, 31')
	#gp('set term png')
	#gp('set output "plotpygnu.png"')
	#plot = Gnuplot.PlotItems.Data(graphDataDivergence, with_ = 'lines',title="huh")
	#gp.splot(graphDataDivergence)

def write3DPlotData(graphData,outputFile):
	f = open(outputFile,'w')
	for point in graphData:
		if round(point[0],2) == 0.0:
			f.write('\n')
		f.write('%f %f %f\n'% (point[0],point[1],point[2]))

def write2DClusterBarData(datasets,file):
	f = open(file,'w')
	header = \
"""# clustered graph example from Derek Bruening's CGO 2005 talk
=cluster;20% regeneration;40% regeneration;60% regeneration;80% regeneration;90% regeneration
# green instead of gray since not planning on printing this
colors=black,yellow,red,med_blue,light_green
=table
yformat=%g%%
max=100
=norotate
legendx=4200
legendy=1450
ylabel=Basic block cache size reduction
# stretch it out in x direction
extraops=set size 1.2,1\n
"""
	#f.write(header)

	#for i in range(len(datasets[0]):
	#	for gdata in datasets:
		

class Ddict(dict):
    def __init__(self, default=None): 
		self.default = default
    def __getitem__(self, key):
		if not self.has_key(key): 
			self[key] = self.default()
		return dict.__getitem__(self, key)

if __name__ == "__main__":
	main()
