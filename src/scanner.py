# coding:utf-8
from netcracker import *
from netcracker_interface import *
from subprocess import Popen, call, PIPE
import os
from os import path, system
from time import time, ctime, sleep
from tempfile import mkdtemp
import sys
from shemutils import Logger

try:
    from tabulate import tabulate
except:
    print "You need to install tabulate. Use 'pip install tabulate' to install it."
    sys.exit(-1)

from signal import SIGINT, SIGTERM

# Static variables
DN = open(os.devnull, "w")
ERRLOG = open(os.devnull, "w")
OUTLOG = open(os.devnull, "w")
logger = Logger("SCAN", logfile="/tmp/netcracker_scanner.log")


def send_interrupt(process):
    """
        Sends interrupt signal to process's PID.
    """
    logger.debug("Interrupting process {0} ...".format(process))
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


def formatTime(t):
    days = 0.0
    hours = 0.0
    minutes = 0.0
    if t > 86400:
        days = (t / 86400)
        hours = (t % 86400) / 3600
        minutes = (t % 3600) / 60
        seconds = ((t % 86400) % 3600) % 60
    elif t > 3600:
        hours = (t / 3600.0)
        minutes = ((t % 3600) / 60)
        seconds = ((t % 3600) % 60)
    elif t > 60:
        minutes = (t / 60)
        seconds = (t % 60)
    else:
        seconds = t

    return "%dd %2.fh %2.fm %2.fs" % (days, hours, minutes, seconds)


def log(string, filename="netcracker.log"):
    hr = str(ctime().replace("  ", " ")).split(" ")[3]
    with open(filename, "a") as f:
        logMsg = "[%s] %s" % (hr, string)
        f.write(logMsg)
    print "Error successfully logged."


class APList:
    def __init__(self):
        self.list = []
        self.length = len(self.list)

    def updateSize(self):
        self.length = len(self.list)


class STList:
    def __init__(self):
        self.list = []
        self.length = len(self.list)

    def updateSize(self):
        self.length = len(self.list)


class AccessPoint:
    def __init__(self, data):
        self.bssid = str(data[0]).replace(" ", "")
        self.channel = str(data[3]).replace(" ", "")
        self.speed = str(data[4]).replace(" ", "")
        self.auth = str(data[5]).replace(" ", "")
        if self.auth == "WPA2WPA":
            self.auth = "WPA2 - WPA"
        self.power = str(data[8]).replace(" ", "")
        self.beacons = str(data[9]).replace(" ", "")
        self.essid = data[13]
        if self.essid[0:1] == " ":
            self.essid = self.essid[1:]
        self.clients = 0
        self.changePower()

    def changePower(self):
        try:
            if int(self.power) != -1:
                self.power = 100 - (int(self.power) * - 1)
        except:
            pass


class Station:
    def __init__(self, data):
        self.mac = str(data[0]).replace(" ", "")
        self.power = str(data[3]).replace(" ", "")
        self.bssid = str(data[5]).replace(" ", "")
        if not self.detectMac(self.bssid):
            self.bssid = GR + "DISCONNECTED" + W
        self.probed = data[6:]
        self.probed = self.parseProbedEssids()

    def parseProbedEssids(self):
        data = self.probed
        essid_str = ""
        if len(data) > 0:
            for essid in data:
                essid_str += "%s, " % (str(essid))
            essid_str = essid_str[:-2]
            if essid_str != " ":
                return str(essid_str).replace("\r", "")
            else:
                return

    def detectMac(self, mac):
        if (len(mac) < 13):
            return False
        else:
            if (mac[2] == ":" and mac[5] == ":" and mac[8] == ":" and mac[11] == ":" and mac[14] == ":"):
                return True
        return False


class Scanner:
    def __init__(self, interface, timeout=0):
        self.interface = None

        logger.info("Initializing scanner ...")

        if self.setupInterfaceForScan(interface) != 0:
            logger.critical("Could not set-up interface to scanning.")
            exit(1)  # exit -1 code for interface error
        if self.CreateTempFolder() != 0:
            logger.critical("Could not create a temporary folder.")
            exit(2)  # exit -2 code for temporary folder error
        if self.createTempData() != 0:
            logger.critical("Could not create temporary data.")
            exit(4)  # exit -4 code for temporary data creation error
        if self.createDataLists() != 0:
            logger.critical("Could not create data lists.")
            exit(5)  # exit -5 code for temporary data lists creation error
        if self.initScan() != 0:
            logger.critical("Could not start scanning.")
            exit(6)  # exit -6 code for launching process of airodump-ng
        if self.countTime(0) != 0:
            logger.critical("Could not count time to scan.")
            exit(7)  # exit -7 for error when start to count time

        print B + "Initializing scan at " + G + "%s" % (ctime()) + W
        if self.getScanData(timeout) != 0:
            exit(8)  # exit -8 for error when scanning

        if self.countTime(1) != 0:
            exit(9)

        self.terminateSimilarProcesses()
        print "-----------"
        print B + "Scan duration:" + G + " %s" % (formatTime(self.end - self.start)) + W

        # if(self.setupInterfaceAfterScan() != 0):
        # print "Error!"
        # exit(-10) #exit -10 if raised error from raising up the interface

    def terminateSimilarProcesses(self):
        send_interrupt(self.process)
        try:
            os.kill(self.process.pid, SIGTEM)
        except:
            pass
        return 0

    def setupInterfaceForScan(self, interface):
        self.interface = Interface(interface)
        if self.interface.changePower("down") != 0:
            logger.error("Could not turn interface {0} down.".format(interface))
            return -1
        if self.interface.changeMode("monitor") != 0:
            logger.error("Could not turn interface {0} into monitor mode.".format(interface))
            return -1
        if self.interface.changeMac(0) != 0:
            logger.error("Could not change mac from interface {0}.".format(interface))
            return -1
        if self.interface.changePower("up") != 0:
            logger.error("Could not turn interface {0} up.".format(interface))
            return -1
        return 0

    def setupInterfaceAfterScan(self):
        if self.interface.changePower("down") != 0:
            return -1
        if self.interface.changeMode("managed") != 0:
            return -1
        if (self.interface.changeMac(1) != 0):
            exit(-1)
        if (self.interface.changePower("up") != 0):
            exit(-1)
        return 0

    def countTime(self, x):
        if (x == 0):
            self.start = time()
        elif (x == 1):
            self.end = time()
        else:
            self.total = formatTime(self.end - self.start)
        return 0

    def clean_screen(self):
        os.system("clear")
        return 0

    def createDataLists(self):
        self.apList = APList()
        self.stList = STList()
        self.probedEssids = []
        self.targets = []
        self.old_targets = []
        return 0

    def createTempData(self):
        self.tempFile = self.temp + "netcracker"
        self.extTempFile = self.tempFile + "-01.csv"
        return 0

    def CreateTempFolder(self, prefix='netcracker'):
        self.temp = mkdtemp(prefix=prefix)
        if not self.temp.endswith(os.sep):
            self.temp += os.sep
        return 0

    def initScan(self):
        self.command = ['airodump-ng', str(self.interface.interface), '-a', '-w', self.tempFile, "--output-format",
                        "csv"]
        self.process = Popen(self.command, stdout=DN, stderr=DN)
        return 0

    def readCsvFile(self, file):
        data = []
        if (path.isfile(file)):
            with open(file, "r") as f:
                for line in f.readlines():
                    data.append(str(str(line).replace("\n", "")).split(","))
            return data
        else:
            return None

    def classifyData(self, data):
        if (len(data) > 13):
            try:
                if (int(data[3]) > 0):
                    ap = AccessPoint(data)
                    return (0, ap)  # return 0 if AP
                else:
                    st = Station(data)

                    """Insere o probed ESSID na lista de ESSIDs para add no db de calcular essids previamente"""
                    data = st.probed.split(", ")
                    for element in data:
                        if (element not in self.probedEssids):
                            self.probedEssids.append(element)

                    return (1, st)
            except Exception as e:
                return (3, None)
        elif (len(data) > 5):
            st = Station(data)
            return (1, st)  # return 1 if ST
        else:
            print data
            return (3, "o")

    def parseApData(self, ap):
        parameters = {"ESSID": (ap.essid, [acp.essid for acp in self.apList.list]),
                      # "Power":(ap.power, [acp.power for acp in self.apList.list]),
                      "BSSID": (ap.bssid, [acp.bssid for acp in self.apList.list]),
                      "Channel": (ap.channel, [acp.channel for acp in self.apList.list])
                      }
        for par in parameters:
            if (parameters[par][0] in parameters[par][1] and parameters[par][0] != par):
                # index = parameters[par][1].index(parameters[par][0])
                # if(parameters["Channel"][0] != )
                return -1

        return 0

    def parseStData(self, st):
        parameters = {"STATION MAC": (st.mac, [stn.mac for stn in self.stList.list]),
                      # "Power":(st.power, [stn.power for stn in self.stList.list]),
                      # "BSSID":(st.bssid, [stn.bssid for stn in self.stList.list]),
                      # "ESSID":(st.probed, [stn.probed for stn in self.stList.list])
                      }
        for par in parameters:
            if (parameters[par][0] in parameters[par][1] and parameters[par][0] != par):
                return -1
        return 0

    def insertAp(self, ap):
        self.apList.list.append(ap)
        self.apList.updateSize()

    def insertSt(self, station):
        self.stList.list.append(station)
        self.stList.updateSize()

    def scanProcedure(self):
        self.apList = APList()
        self.stList = STList()
        data = self.readCsvFile(self.extTempFile)
        if (data is not None):  # only print if data has data
            for line in data:
                code, object = self.classifyData(line)
                if (code == 0):  # if is AP
                    # if(self.parseApData(object) == 0):
                    self.insertAp(object)
                elif (code == 1):
                    # if(self.parseStData(object) == 0):
                    self.insertSt(object)
            self.printDataOnScreen()
            print B + "Scan duration: " + G + "%s" % (formatTime(time() - self.start)) + W
        else:
            print R + "No data to read." + W

    def timeOutSetting(self, timeout):
        x = time()
        if (timeout == 0):
            timeout = (x * 2)
        else:
            timeout = x + timeout
        return x, timeout

    def getScanData(self, timeout):
        x, timeout = self.timeOutSetting(timeout)

        APCount = 0
        STCount = 0
        while x < timeout:
            x = time()
            try:
                sleep(5)
                self.scanProcedure()
            except KeyboardInterrupt:
                self.scanProcedure()
                print "User has aborted the scanning procedure."
                print "Temp file location: %s" % (self.extTempFile)
                return 0
                # except Exception as e:
                # log("Error on getScanData: %s" % (str(e)))
                # pass
        return 0

    def popCaption(self, listLength, list, item="BSSID"):
        if (listLength > 0 and item in [plh.bssid for plh in list]):
            items = [str(plh.bssid).replace("\r", "") for plh in list]
            wr = items.index(str(item).replace(" ", ""))
            list.pop(wr)
            return 0
        return -1

    def detectMac(self, mac):
        if (len(mac) < 13):
            return False
        else:
            if (mac[2] == ":" and mac[5] == ":" and mac[8] == ":" and mac[11] == ":" and mac[14] == ":"):
                return True
        return False

    def colorizePower(self, number):
        if (number < 10):
            return RED + str(number) + "db" + W
        elif (number < 30):
            return YELLOW + str(number) + "db" + W
        else:
            return GREEN + str(number) + "db" + W

    def insertDataToTable(self, origin, destination, key):
        for item in origin:
            if (key == 0):
                destination.append([item.bssid, item.essid, item.power, item.channel, item.auth, item.clients])
            else:
                if (self.detectMac(item.mac)):
                    destination.append([item.bssid, item.mac, item.power, item.probed])
        destination = self.sortTable(destination)

    def sortTable(self, table):
        try:
            return sorted(table, key=lambda x: (x[2], x[0]), reverse=False)
        except:
            return [[]]

    def colorizeHeader(self, list):
        """This function is not being used at the moment."""
        for item in list:
            list[list.index(item)] = G + str(item) + W

    def checkClient(self, apTable, stTable):
        for accesspoint in apTable:
            try:
                if (int(accesspoint[5])):
                    accesspoint[5] = 0
            except:
                pass

        for client in stTable:
            if (len(client) > 0 and client[2] != "-1"):
                stBssid = client[0]
                if (self.detectMac(stBssid)):
                    if (stBssid in [ap[0] for ap in apTable]):
                        index = [ap[0] for ap in apTable].index(stBssid)
                        apTable[index][5] += 1
                        if stBssid in [a.bssid for a in self.apList.list]:
                            index = [a.bssid for a in self.apList.list].index(stBssid)
                            self.apList.list[index].clients += 1
        return

    def formatPower(self, table):
        for ap in table:
            ap[2] = "%s" % (self.colorizePower(int(ap[2])))
            if type(ap[1]) == str and len(ap[1]) > 15:
                ap[1] = ap[1][:15] + "..."

    def printDataOnScreen(self):
        if self.clean_screen() == 0:
            """Cria as estruturas para o tabulate"""
            ap_table = []
            st_table = []

            """Aqui sao inseridos as estruturas de dados nas tabelas temporarias"""
            self.insertDataToTable(self.apList.list, ap_table, 0)
            self.insertDataToTable(self.stList.list, st_table, 1)

            """So vai sortar se tiver elementos"""
            if len(ap_table) > 1:
                ap_table = self.sortTable(ap_table)
                self.formatPower(ap_table)
            if len(st_table) > 1:
                st_table = self.sortTable(st_table)
            self.checkClient(ap_table, st_table)

            '''Printa os dados'''
            print tabulate(ap_table, headers=[BG + BOLD + 'BSSID' + W, BG + BOLD + 'ESSID' + W, BG + BOLD + 'POWER' + W,
                                              BG + BOLD + 'CHANNEL' + W, BG + BOLD + 'AUTH' + W,
                                              BG + BOLD + "CLIENTS" + W], tablefmt="fancy_grid")
            # print tabulate(st_table, headers=[G + "BSSID" + W,G + "STATION MAC" + W,G + "POWER" + W,G + "ESSIDs" + W], tablefmt="fancy_grid")
        else:
            exit(-3)  # exit -3 code for error when printing on screen
