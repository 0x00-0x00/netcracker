# coding:utf-8
import os
from wordlist import *
from os import mkdir, path, remove
from shutil import copy

#  Define the project data folder
project_folder = os.environ["HOME"] + os.sep + ".netcracker" + os.sep

def custom_procedure(essid):
    formatted_essid = splitter(str(essid))
    data_holder = []
    if type(formatted_essid) == list:
        for f_essid in formatted_essid:
            gen = generateEssidPasswords(f_essid)
            try:
                while True:
                    data_holder.append(gen.next())
            except StopIteration:
                print "Done generating custom passwords for ESSID '%s'" % (str(f_essid))
    else:
        gen = generateEssidPasswords(formatted_essid)
        try:
            while True:
                data_holder.append(gen.next())
        except StopIteration:
            print "Done generating custom passwords for ESSID '%s'" % (str(formatted_essid))
    return data_holder


def is_cracked(x):
    if str(x) != "None":
        return -1
    else:
        return 0


def create_wordlist(data):
    if path.isfile("/tmp/netcracker_temporary_file"):
        remove("/tmp/netcracker_temporary_file")
    try:
        with open("/tmp/netcracker_temporary_file", "w") as f:
            for line in data:
                try:
                    f.write(line.decode("utf-8") + "\n")
                except UnicodeDecodeError:
                    pass
                except UnicodeEncodeError:
                    pass
        return 0
    except Exception as e:
        print "ERROR: %s" % (str(e))
        pass


def format_status(status):
    if status == "UNCRACKED":
        return R + status + W
    else:
        return G + status + W


def printMenu(data, header, db):
    print BOLD + "\n______________\nAvailable %s:" % header + W
    if len(data) == 0:
        print "No available %s yet." % header
        return
    for x in xrange(len(data)):
        if header.lower() == "handshakes":
            d = len(getData(db, "WORDLISTS"))
            wls = len(str(data[x][6]).split(",")) - 1
            p = (wls / float(d)) * 100
            if p < 10:
                p = R + "%0.f" % p + "%" + W
            elif 30 < p < 70:
                p = YELLOW + "%0.f" % p + "%" + W
            else:
                if p > 100:
                    p = 100.0
                p = G + "%0.f" % p + "%" + W
            if data[x][5] == "UNCRACKED":
                essid = GR + str(data[x][1]) + W
            else:
                essid = G + str(data[x][1]) + W
            print "%s. %s [%s]" % (str(x + 1), essid, p)
        else:
            print "%s. %s" % (str(x + 1), G + str(data[x][1]) + W)
    return


def countLines(file):
    with open(file, 'r') as f:
        return len(f.readlines())


def printSQLWordlistTableSituation(situation, table):
    if situation == 0:
        print "[" + G + "!" + W + "] " + "New password table '%s' created!" % table
    if situation == 1:
        print "[" + G + "!" + W + "] " + "Using old table '%s'." % table
    return


def turnToAlpha(word):
    return word[0:1].upper() + word[1:].lower()


class Word:
    def __init__(self, word):
        word = str(word).replace(" ", "")
        self.lower = word.lower()
        self.upper = word.upper()
        self.alpha = turnToAlpha(word)


def parseWL(file):
    numeric = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    with open(file, "r") as f:
        for line in f.readlines():
            n = False
            line = str(str(line).replace(" ", "")).replace("\n", "")
            for char in line:
                if char in numeric:
                    n = True
                    break
            if n is not True:
                w = Word(line)
                yield w.lower
                yield w.upper
                yield w.alpha
            else:
                if len(line) > 7:
                    yield line


def jumpNextTarget():
    print R + "INTERRUPT DETECTED!" + W + G + " Jumping to next target...                            " + W


def printSkip(essid, bssid):
    print "\n[" + G + "!" + W + "] Skipping AP %s [%s] as it is already in captured state.                  " % (
        BOLD + G + essid + W, BOLD + G + bssid + W)


def printAvailableAPsToAttack(ap_list):
    if len(ap_list) > 0:
        print "\n______________\n%sAvailable APs:%s\n" % (BOLD, W)
        for i in xrange(len(ap_list)):
            print "%s. %s" % (i + 1, G + str(ap_list[i].bssid) + W + " - " + G + str(ap_list[i].essid) + W)


def filterCandidatesWPACapture(ap_list):
    attack = []
    for ap in ap_list:
        if ap.clients > 0 and "WPA" in ap.auth and str(ap.essid).replace(" ", "") != "":
            attack.append(ap)
    return attack


def returnObjects(scanner_obj):
    aps = scanner_obj.apList.list
    sts = scanner_obj.stList.list
    pes = scanner_obj.probedEssids
    return aps, sts, pes


def copyFileToRepository(f, newname=None):
    if path.isfile(f):
        try:
            if not newname:
                copy(f, "/usr/share/netcracker/handshakes/uncracked/")
            else:
                copy(f, "/usr/share/netcracker/handshakes/uncracked/" + str(newname).replace(" ", ""))
        except Exception as e:
            print "ERROR: %s" % (str(e))


def extractData(f):
    with open(f, "rb") as f:
        data = f.read()
    return data


def createMainFolder(d=project_folder):
    main_dir = project_folder
    subfolders = ["handshakes", "database", "handshakes/cracked", "handshakes/uncracked"]
    if path.isdir(main_dir) is False:
        mkdir(main_dir)
        for folder in subfolders:
            mkdir(main_dir + folder)
    return


def verify(obj):
    status, essid, bssid = obj.checkHandshakeStatus()
    if status == 1:
        print BOLD + "File ...: %s %scontains%s%s handshakes. \n[ESSID: %s, BSSID: %s]" % (
            obj.inputFile.base, G, W, BOLD, G + essid + W + BOLD, G + bssid + W + BOLD) + W
        return 0, essid, bssid
    else:
        print BOLD + "File: %s %sdoes not%s contains handshakes." % (obj.inputFile.base, R, W) + W
        return -1, essid, bssid
