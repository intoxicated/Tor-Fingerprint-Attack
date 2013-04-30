import os
#My
class Packet:
	"Packet"
	SRC=-5
	DST=-5
	length=-5
	typeOf=""
	Time=-5
	RTT=-5
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
		except:
			self.number=-1337
	def __repr__(self):
		return "number: "+str(self.number)+" "+str(self.SRC)+"->"+str(self.DST)+" size="+str(self.length)+" Flags: "+self.typeOf+" Time: "+str(self.Time)+" RTT="+str(self.RTT)+'\n'
	def valid(self):
		if(self.number==-1337):
			return False
		else:
			return True


class mySigReader:
	"an object to represent a flow"
	packetList=list()
	DBFile="ourDefinitions.txt"
	Rules=[40,80,160,320,600,700,1180,1375,1450,1600,1800,3500]
	ProbVector1=[0,0,0,0,0,0,0,0,0,0,0,0,0]
	def __init__(self):
		2+2
	def loadDB(self,lineNumber):
		2+2
	def loadPCFile(self,file):
		self.clean()
		a = os.popen("tshark -r "+file+" -Tfields -e frame.number -e ip.src -e ip.dst -e frame.len -e tcp.flags -e frame.time_relative -e tcp.analysis.ack_rtt -E header=y -E separator=,")
		for line in a.readlines():
			if(line!=""):
				temp=line.split(',')
				a = Packet(temp[0],temp[1],temp[2],temp[3],temp[4],temp[5],temp[6].strip("\n"))
				if(a.valid()):
					self.packetList.append(a)
					print a
	def writeDB(self):
		2+2
	def clean(self):
		del self.packetList[:]
