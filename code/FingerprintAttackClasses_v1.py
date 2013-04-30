#!/usr/bin/python
import os,operator,math

class Packet:
	"""Packet: smallest sized data unit"""
	def __init__(self,number,SRC,DST,length,typeOf,Time,RTT):
		try:
			self.number=int(number,10)#10 is NECCESARY 
			self.SRC=SRC
			self.DST=DST
			self.length=int(length,10)
			self.typeOf=typeOf
			self.Time=float(Time)
			if(RTT!=""):
				self.RTT=float(RTT)
			else:
				self.RTT=-99
		except:
#			print "Failed to grab a packet\n"
			self.number=-1337
	def __repr__(self):
		return "number: "+str(self.number)+" "+str(self.SRC)+"->" \
			+str(self.DST)+" size="+str(self.length)+" Flags: "+ \
			self.typeOf+" Time: "+str(self.Time)+" RTT="+str(self.RTT)
	def valid(self):
		if(self.number==-1337):
			return False
		else:
			return True

class SimplePacketList:
	"""
		This class represents a set of packets indexed by time.

		The caller of the class must maintain what this list holds (i.e.
		this class can be used to hold a single stream or a multistreamed
		data set). 
	"""
	def __init__(self):
		self.packetList = list()
		self.failedPacketAttempts = 0
	def loadFromPCAP(self,file):
		self.clean()
		a = os.popen("tshark -r "+file+" -Tfields -e frame.number -e ip.src \
			-e ip.dst -e frame.len -e tcp.flags -e frame.time_relative -e \
			tcp.analysis.ack_rtt -E header=y -E separator=,")
		for line in a.readlines():
			if(line!=""):
				temp=line.split(',')
				p = Packet(temp[0],temp[1],temp[2],temp[3],temp[4],temp[5],
					temp[6].strip("\n"))
				# if the packet succeeded we add it to the list, and if not
				# we increment a failed packets read flage
				if(p.valid()):
					self.packetList.append(p)
				else:
					self.failedPacketAttempts = operator.iadd(\
						self.failedPacketAttempts,1)
#		print self.failedPacketAttempts
	def addPacket(self,packet):
		# if we have an item in the list and the timestamp of the new packet
		# is greater than the last packet in the list we add it to the list
		if self.packetList:
			if self.packetList[-1].Time < packet.Time and packet.valid():
				self.packetList.append(packet)
			else:
				print "Packets were added out of order! Badness in your code!\n"
				print "Last Packet\n\t" + self.packetList[-1].__repr__()
				print "Next Packet\n\t" + packet.__repr__()
				import sys
				sys.exit(1)
		else: 
			self.packetList.append(packet)
	def __repr__(self):
		for i in self.packetList:
			print i
	def clean(self):
		del self.packetList[:]

class WebsiteFingerprint:

	def __init__(self):
		self.probVectSet = {}
		# prob vector 1: packet size counter
		#self.prv1 = list()
		self.PacketRanges = ( (0,599),(600,699),(700,1449),(1450,3500))
		#for i in range(len(self.PacketRanges)):
		#	self.prv1.append([0,0])
		self.prv1 = ProbDistribution(len(PacketRanges))

	def __cmp__(self):
		pass
	def loadFromStreamData(self,streamSet):
		"""Collects information for a set of packet lists, effectively
		   creating an average probability distribution over the set of
		   streams.
		"""
		print "We have " + str(len(streamSet)) +" different streams being " + \
			"processed inside of createFromMutliStream()"

		# process packet counts
		# fill out prob distribution vectors with the counts
		for stream in streamSet:
			for p in stream.packetList:
				# number of packets per size interval
				sizeIndex = self.findSizeIndex(p.length)
				self.prv1[sizeIndex][0] += 1
				# inter-packet timing

				# number of packets from website to host

				# throughput/ack useful calcs... rtt type prob vector
			print self.prv1

			self.probVectSet["prv1"] = self.prv1

		self.normalize(streamSet,self.probVectSet)
		
		# print out the goodness
		for i in range(len(self.PacketRanges)):
			print "Packet Range: " + str(self.PacketRanges[i][0]) + "-" +\
				str(self.PacketRanges[i][1]) + " Average Number: " + \
				str(self.prv1[i][0]) + " Probability: " + str(self.prv1[i][1])

	def normalize(self,streamSet,probVectorSet):
		""" This function will normalize the count vector. 

			It then calculates the probability vector. 
		"""
		for key in probVectorSet:
			sum = 0.0
			# divide each count by the total number of streams we are 
			# processing to get an average
			for index in probVectorSet[key]:
				# normalize the number of hits per packet size
				index[0] = 1.0*index[0] / len(streamSet)
				# add up the total number of packets to calc the probability 
				# at each index
				sum += index[0]
			# now calculate the probability distribution by taking the 
			# statistical percentage of overall packets at each index 
			for index in probVectorSet[key]:
				index[1] = index[0]/sum

	def writeToDB(self,website,dbDirName="KnownFingerprints"):
		try:
			os.listdir(dbDirName)
		except:
			os.mkdir(dbDirName)
		dbfile = open(dbDirName+"/"+website,'w')
		for key,val in self.probVectSet.items():
			dbfile.write(key+":"+str(val)+"\n")

	def loadFromDB(self,dbFileName):
		"""
			This method takes the filename of a db file and opens the file
			for reading. It then reads line by line, expecting each line to 
			be a unique probabilty vector for the fingerprint.
		"""
		dbfile = open(dbFileName,'r')
		for line in dbfile.readlines():
			if(line!=""):
				# list to hold tmp values of prob vector
				tmpList = list()
				# this will create a two element list: [0] the name of the prob 
				# vector and [1] the value in a string of the vector
				temp = line.split(':')
				temp[-1].strip("\n")
				probData = temp[1][1:-2]
				probData = probData.split('], [')
				probData[0] = probData[0][1:]
				probData[-1] = probData[-1][:-1]
				for i in probData:
					count,prob = i.split(', ')
					tmpList.append([float(count),float(prob)])
				# add the 2-d array to the vector list		
				self.probVectSet[temp[0]] = tmpList
				"""
				# print out the goodness
				for i in range(len(self.PacketRanges)):
					print "Packet Range: " + str(self.PacketRanges[i][0]) + "-" +\
						str(self.PacketRanges[i][1]) + " Average Number: " + \
						str(self.probVectSet[temp[1]][i][0]) + " Probability: " + \
						str(self.probVectSet[temp[1]][i][1])
				"""
	def getKLDivergence(self,known,unknown):
		sum = 0.0
		sum2 = 0.0

		sum2 = known.probVectSet["prv1"][2][1] * \
			math.log(known.probVectSet["prv1"][2][1] / \
			unknown.probVectSet["prv1"][2][1])
		sum2 += known.probVectSet["prv1"][3][1] * \
			math.log(known.probVectSet["prv1"][3][1] / \
			unknown.probVectSet["prv1"][3][1])

		for i in range(len(known.probVectSet["prv1"])):
		#for key,arr in known.probVectSet.items():
			#print "This is the key: " + key
			"""
			print "This is the known: " 
			print known.probVectSet["prv1"]
			print "This is the unknown array: " 
			print unknown.probVectSet["prv1"]
			"""
			#for i in range(len(arr)):
			if known.probVectSet["prv1"][i][1] != 0 and \
				unknown.probVectSet["prv1"][i][1] != 0:
				sum += known.probVectSet["prv1"][i][1] * \
					math.log(known.probVectSet["prv1"][i][1] / \
					unknown.probVectSet["prv1"][i][1])
		print "KL-Divergence is: " + str(sum)				
		print "KL-Divergence 2 is: " + str(sum2)				
			
	
	def findSizeIndex(self,size):
		for index in range(len(self.PacketRanges)):
			if size >= self.PacketRanges[index][0] and \
				size <= self.PacketRanges[index][1]:
					return index

class ProbDistribution:
	def __init__(self,indexLen):
		self.countVector = []
		self.probVector = []
		for i in range(indexLen):
			self.countVector.append(0)
			self.probVector.append(0)

	def normalize(self,streamSet,probVectorSet):
		""" This function will normalize the count vector. 

			It then calculates the probability vector. 
		"""
		for key in probVectorSet:
			sum = 0.0
			# divide each count by the total number of streams we are 
			# processing to get an average
			for index in probVectorSet[key]:
				# normalize the number of hits per packet size
				index[0] = 1.0*index[0] / len(streamSet)
				# add up the total number of packets to calc the probability 
				# at each index
				sum += index[0]
			# now calculate the probability distribution by taking the 
			# statistical percentage of overall packets at each index 
			for index in probVectorSet[key]:
				index[1] = index[0]/sum

if __name__ == "__main__":
	print "Run by self as script, and starting test modules\n"
	test2()

def test2():
	pass
def test1():
	# test the simple packet lists add function
	ip = "0.0.0.0"
	type = "0xff"
	one = "1"
	p1 = Packet("1",ip,ip,one,type,"1","0")
	p2 = Packet("4",ip,ip,one,type,".5","1")
	p3 = Packet("8",ip,ip,one,type,"2","34")
	print p1
	print p2
	print p3
	packetList = SimplePacketList()
	packetList.addPacket(p1)
	packetList.addPacket(p2)
	packetList.addPacket(p3)
	
