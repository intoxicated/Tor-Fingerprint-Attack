#This is my first python codin
#!/usr/bin/python
#AutoDataCollection impelemtation 
#create : 1/27/10
#modified : 1/27/10
#by Real_Free

from autoDataClass import *
import sys, getopt

# list = name of txt file that contains  list of urlName,urlAddr form
def runAuto(list = ""):
	try:
		fo = open(list, "r+")
	except IOError:
		print "fail to open file"
		sys.exit(2)
    # autoData array[30]; declare and initialize autoData type array to store obj ? 
	for line in fo: 
		objs = autoData()
		str = line.split(',')
		objs.urlName = str[0] # storing name of url 
		objs.urlAddr = str[1] # storing address of url 
		print "name of url: " + objs.urlName
		print "addr of url: " + objs.urlAddr
        #george's function will go on here with two arguments urlName, urlAddr
        #if george's function return obj with number of data in it
		#may able to fix code to gather all information into one object
		#store its object into dyanmic array 
		#and end of iterantion return to array
        
def main():
	runAuto("list.txt")

if __name__ == "__main__":
	main()




