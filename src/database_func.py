# coding:utf-8
from netcracker.database import *
from os import system, path
from time import time
from shutil import copy


def accessDatabase(name="/opt/netcracker/database/netcracker.db"):
    db = Database(name)
    db.text_factory = lambda x: unicode(x, "utf-8", "ignore")
    return db


def closeDatabase(dbObject):
    dbObject.close()
    return


def executeQuery(db, query):
    try:
        db.cursor.execute(query)
        return 0
    except Exception as e:
        print "ERROR: %s" % (str(e))
        return -1


def insertCrackedStatus(db, bssid, password):
    SQL1 = "UPDATE HANDSHAKES SET status = 'CRACKED' WHERE bssid='%s'" % bssid
    SQL2 = "UPDATE HANDSHAKES SET password = '%s' WHERE bssid='%s'" % (str(password).replace("'", ''), bssid)
    if executeQuery(db, SQL1) != 0:
        print "Error on SQL Query #1"
    if executeQuery(db, SQL2) != 0:
        print "Error on SQL Query #2"
    db.handle.commit()


def insertNewRunnedWordlist(db, bssid, wordlist_name):
    SQL1 = "SELECT wordlists FROM HANDSHAKES WHERE bssid = '%s'" % bssid
    if executeQuery(db, SQL1) != 0:
        print "Error on SQL Query #1."
    DATA1 = [x[0] for x in db.cursor.fetchall()][0]
    if DATA1 is not None:
        names = [str(x).replace(" ", "") for x in DATA1.split(",")]
        DATA2 = DATA1 + ", %s" % (wordlist_name)
    else:
        names = []
        DATA2 = "%s" % (wordlist_name)
    SQL2 = "UPDATE HANDSHAKES SET wordlists = '%s' WHERE bssid = '%s'" % (DATA2, bssid)
    if wordlist_name not in names:
        if executeQuery(db, SQL2) != 0:
            print "Error on SQL Query #2."
    else:
        return -1
    db.handle.commit()
    return 0


def resetWordlistHistory(db, bssid):
    """This function uses a db object and a string containing a bssid to reset wordlist history of cracking from a
    stored pcap file information."""
    SQL1 = "UPDATE HANDSHAKES SET wordlists = '' WHERE bssid = '%s'" % (bssid)
    if executeQuery(db, SQL1) != 0:
        print "Error on SQL Query #1."
        return -1
    return 0


def getData(db, table):
    """This function uses a db object and a string containing a table name to retrieve data from database."""
    SQL = "SELECT * FROM %s" % (table)
    if executeQuery(db, SQL) != 0:
        return -1
    return [x for x in db.cursor.fetchall()]


def createTables(dbObject):
    """This function uses a db object to create sql tables if they do not exist."""
    SQL = [
        "CREATE TABLE IF NOT EXISTS HANDSHAKES (id INTEGER PRIMARY KEY AUTOINCREMENT, essid TEXT, bssid TEXT, file_location TEXT, file_capture TEXT, status TEXT, wordlists TEXT, password TEXT)",
        "CREATE TABLE IF NOT EXISTS PROBED_ESSIDS (id INTEGER PRIMARY KEY AUTOINCREMENT, essid TEXT)",
        "CREATE TABLE IF NOT EXISTS WORDLISTS (id INTEGER PRIMARY KEY AUTOINCREMENT, tableNames TEXT)"
        ]
    for sql in SQL:
        dbObject.cursor.execute(sql)  # execute SQL statements
    dbObject.handle.commit()  # save changes


def queryWLTableNames(db):
    QUERY1 = "SELECT tableNames from WORDLISTS"
    db.cursor.execute(QUERY1)
    data = db.cursor.fetchall()
    return [x[0] for x in data]


def removeWordlistTable(db, table_name):
    """This function will delete one of the wordlist tables."""
    tables = queryWLTableNames(db)
    if table_name.upper() in tables:
        QUERY1 = "DELETE FROM WORDLISTS WHERE tableNames='%s'" % (table_name.upper())
        db.cursor.execute(QUERY1)
        db.handle.commit()
        return 0  # retorna 0 se tiver e deletar
    return 1  # retorna 1 se nao tiver na lista


def removeTableProcedure(db, table):
    if removeWordlistTable(db, table) == 0:
        print "[" + G + "!" + W + "] Table '%s' was successfully deleted." % (table)
    elif removeWordlistTable(db, table) == 1:
        print "[" + G + "!" + W + "] Table '%s' does not exists." % (table)


def createWordlistTable(db, table_name):
    """This function will create a SQL table to hold data from wordlist file."""
    tables = queryWLTableNames(db)
    if table_name.upper() not in tables:
        QUERY1 = "INSERT INTO WORDLISTS VALUES (NULL, '%s')" % (table_name.upper())
        db.cursor.execute(QUERY1)
        QUERY2 = "CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY AUTOINCREMENT, word TEXT)" % (
        table_name.upper())
        db.cursor.execute(QUERY2)
        db.handle.commit()
        return 0  # retorna 0 se a tabela nao existir
    return 1  # retorna 1 se ja existir a tabela


def gatherWords(db, table_name):
    """This function will recover all the already stored words in database and retrieve it to a variable."""
    try:
        QUERY = "SELECT word FROM %s" % (table_name.upper())
        db.cursor.execute(QUERY)
        data = db.cursor.fetchall()
        return [x[0] for x in data]
    except:
        return -1


def registerWord(db, word, table_name):
    """This function will insert a word into wordlist database."""
    try:
        SQL = "INSERT INTO %s VALUES (NULL, '%s')" % (table_name.upper(), word)
        db.cursor.execute(SQL)
        """O Commit tem que ser feito depois do procedimento porque eu tirei o commit da funcao"""
        return 0
    except:
        return -1


def copyFileToRepository(file, newname=None):
    if path.isfile(file):
        try:
            if newname == None:
                copy(file, "/usr/share/netcracker/handshakes/uncracked/")
            else:
                copy(file, "/usr/share/netcracker/handshakes/uncracked/" + str(newname).replace(" ", ""))
        except Exception as e:
            print "ERROR: %s" % (str(e))


def registerNewHandshake(db, file, ap_data):
    """This function is actually a procedure.
    Procedure: functions that call functions in logical order"""
    newName = "%s_%s.cap" % (str(ap_data[0]).replace("\n", ''), str(ap_data[1]).replace("\n", ''))
    copyFileToRepository(file, newname=newName)
    addPcapFile(db, file, ap_data)


def queryProbedEssids(db):
    """This function uses a database object to return a list with all the probed ESSIDS from the
    PROBED_ESSIDS sql table."""
    SQL = "SELECT essid FROM PROBED_ESSIDS"
    db.cursor.execute(SQL)
    data = db.cursor.fetchall()
    l = [None] * len(data)
    for x in xrange(len(data)):
        l[x] = data[x][0]
    return l


def addProbedEssid(db, probed_essid):
    try:
        SQL = "INSERT INTO PROBED_ESSIDS VALUES (NULL, '%s') " % (probed_essid)
        db.cursor.execute(SQL)
        db.handle.commit()
        return 0
    except Exception as e:
        return -1


def checkProbedEssid(dbData, pE):
    if pE in dbData:
        return -1
    else:
        return 0


def insertProbedEssid(db, probed_essid, dbData):
    if checkProbedEssid(dbData, probed_essid) != 0:
        # print R+"Error on checkProbedEssid function!"+W
        return -1
    if addProbedEssid(db, probed_essid) != 0:
        # print R+"Error on addProbedEssid function!"+W
        return -1
    print "[" + G + "!" + W + "] " + "%sNew%s probed ESSID added to your %scollection%s: %s%s%s" % (
    G, W, G, W, YELLOW, probed_essid, W)
    return 0


def probedProcedure(pes, db, dbData):
    print "\n______________\n%sProbed Essids%s: \n" % (BOLD, W)
    x = 0
    if len(pes) != 0:
        print "[" + G + "!" + W + "] " + G + "%d" % (len(pes)) + W + " probed ESSIDs were detected during this scan."
        for essid in pes:
            if insertProbedEssid(db, essid, dbData) != 0:
                pes.remove(essid)
                continue
            x += 1
        if len(pes) > 0:
            print "[" + G + "!" + W + "] " + G + "%d" % (x) + W + " of them are new essids!"
    else:
        print R + "0" + W + " probed ESSIDs were detected during this scan."
    return 0


def getCapturedAPs(db):
    """This function uses a db object to query all bssids from handshakes table."""
    QUERY = "SELECT bssid from HANDSHAKES"
    db.cursor.execute(QUERY)
    data = db.cursor.fetchall()
    return [str(x[0]).replace("-", ":") for x in data]


def addPcapFile(db, pcap_file, ap_data):
    """This function uses a db object file, a string of a pcap file, and a tuple (essid, bssid) to register a
     handshake into the handshake database."""
    essid = ap_data[0]
    bssid = ap_data[1]
    QUERY = "SELECT bssid FROM HANDSHAKES WHERE bssid='%s'" % (bssid)
    db.cursor.execute(QUERY)
    fetch = db.cursor.fetchall()
    if bssid in [a[0] for a in fetch]:
        print BOLD + G + "This handshake is already registered in database." + W
        return -1
    SQL = "INSERT INTO HANDSHAKES VALUES (NULL, '%s', '%s', '%s', '%s', 'UNCRACKED', NULL, NULL)" % (
    str(essid).replace("\n", ""), str(bssid).replace("\n", ""), pcap_file, str(time()))
    db.cursor.execute(SQL)
    db.handle.commit()
    return 0
