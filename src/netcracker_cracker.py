# coding:utf-8
import os
from netcracker import *
from os import path, remove
from subprocess import Popen, call, PIPE
from signal import SIGINT, SIGTERM
from tempfile import mkdtemp
from random import randrange
from time import sleep
from sys import stdout
from shemutils import Logger

write = stdout.write
flush = stdout.flush
# Static variables
DN = open(os.devnull, "w")
ERRLOG = open(os.devnull, "w")
OUTLOG = open(os.devnull, "w")
logger = Logger("CRACKER", logfile="/tmp/netcracker_cracker.log")


def breakProcess(proc):
    send_interrupt(proc)
    try:
        os.kill(proc.pid, SIGTERM)
    except:
        pass


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


class PCAP:
    def __init__(self, filename):
        self.absolute = path.abspath(filename)
        self.base = path.basename(filename)
        self.dirname = path.dirname(filename)


class Crack:
    def __init__(self, pcap_file):
        if path.isfile(pcap_file) is False:
            logger.critical("File '{0}' was not found.".format(pcap_file))
            exit(1)

        """Criamos as pastas temporarias para guardar os arquivos"""
        if self.CreateTempFolder():
            logger.critical("Error creating temporary folders.")
            exit(1)

        """Validamos a existencia do arquivo e retornamos o caminho absoluto"""
        self.fvCode, self.inputFile = self.checkFileExists(pcap_file)
        if self.fvCode:  # File is invalid
            logger.critical("File is invalid.")
            exit(1)

    def crackHandshake(self, wl_file, program="pyrit"):
        try:
            # command = "pyrit -r %s -i %s attack_passthrough" % (self.inputFile.absolute, wl_file)
            command = ["pyrit", "-r", self.inputFile.absolute, "-i", wl_file, "attack_passthrough"]
            outputfile = self.generateRandomFileName()
            print GR + "Temporary file: %s" % (outputfile) + W
            proc = Popen(command, stdout=open(outputfile, "w"), stderr=open(outputfile, "w"))
            print G + "Cracking process started..." + W
            done = False
            while done == False:
                data = None
                while path.isfile(outputfile) == False:
                    sleep(1)
                with open(outputfile, "r") as f:
                    data = str(f.read()).split("\n")
                    first = data[len(data) - 3:len(data) - 2]
                    second = data[1:2]
                    # print first, second
                    if (len(first) > 0 and len(second) > 0):
                        l = [first[0], second[0]]
                    else:
                        l = [first, second]
                    for x in l:
                        code, dt = self.parsePyritCrackingOutput(x)
                        # print "parsed code: %s and dt %s" % (str(code), str(dt))
                        if (code == 1 or code == 2):
                            self.printPyritOutput(code, dt)
                            done = True
                            breakProcess(proc)
                        if (code == 2):
                            return dt
                    for x in data[len(data) - 1:]:
                        y = x.split("\r")
                        z = y[len(y) - 2]
                        # print "X: %s\nY: %s\nZ: %s" % (str(x), str(y), str(z))
                        code, dt = self.parsePyritCrackingOutput(z)
                        # print code, dt
                        if (code != -1):
                            self.printPyritOutput(code, dt)
                sleep(5)
            breakProcess(proc)
            return 0
        except KeyboardInterrupt:
            print R + "Cracking process cancelled by operator." + W
            breakProcess(proc)
            return -1

    def printPyritOutput(self, code, data):
        if code == 0:  # running
            tried = data[0]
            psec = data[1]
            flush()
            write("%sPasswords: %s | Passwords/sec: %s     \r" % (W, YELLOW + str(tried) + W, YELLOW + str(psec) + W))
            return 0
        if code == 1:  # not found
            flush()
            write(GR + "\nPassword is not in this wordlist.\n" + W)
            return 1
        if code == 2:  # found
            flush()
            write("\n%s\n" % (BOLD + YELLOW + data + W))
            return 1
        return 0

    def parsePyritCrackingOutput(self, line):
        class ParseData:
            not_found = "Password was not found."
            tries = "Tried"
            found = "The password is "

        p = ParseData()
        try:
            if p.not_found in line:
                return 1, None
            if p.tries in line:
                fpmk = line.index("PMK") - 1
                tried = line[6:fpmk]

                fim = line.index("per second") - 6
                inicio = line.index(";") + 2
                perSecond = line[inicio:fim]

                return 0, (tried, perSecond)
            if p.found in line:
                return 2, line
            return -1, None
        except:
            return -1, None

    def checkHandshakeStatus(self):
        command = "pyrit -r %s analyze" % (self.inputFile.absolute)
        pyritOutput = self.returnOutput(command)
        status, essid, bssid = self.parseVerificationPyritPcapFile(pyritOutput)
        if (status == 1):
            return (status, essid, bssid)
        else:
            return status, essid, bssid

    def parseVerificationPyritPcapFile(self, output):
        success = "spread"
        essid = "AccessPoint"
        for line in output:
            if essid in line:
                essid = str(str(line[36:]).replace("'):", "")).replace("\n", "")
                bssid = str(str(line[16:33]).replace(":", "-")).upper()
        for line in output:
            if (success in line):
                return 1, essid, bssid
        return 0, None, None

    def generateRandomFileName(self, prefix="netcracker"):
        r = self.temp + prefix + "_" + "%d.tmp" % (randrange(10000, 1000000))
        while (path.isfile(r)):
            r = prefix + "_" + "%d.tmp" % (randrange(10000, 1000000))
        return r

    def returnOutput2(self, command):
        data = []
        self.outputFileName = self.generateRandomFileName()
        proc = Popen(command, shell=True, stdout=open(self.outputFileName, "w"), stderr=DN)
        while (proc.poll() == None):
            sleep(0.5)
        with open(self.outputFileName, "r") as f:
            for line in f.readlines():
                data.append(line)
        return data

    def returnOutput(self, command):
        proc = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        while proc.poll() == None:
            sleep(0.5)
        data = str(proc.communicate()).split("\n")
        data = str(data[0]).split("\\n")
        return data

    def checkFileExists(self, file):
        if path.isfile(file):
            absoPath = path.abspath(file)
            return 0, PCAP(absoPath)
        else:
            return -1, None

    def CreateTempFolder(self, prefix='netcracker'):
        self.temp = mkdtemp(prefix=prefix)
        if not self.temp.endswith(os.sep):
            self.temp += os.sep
        return 0
