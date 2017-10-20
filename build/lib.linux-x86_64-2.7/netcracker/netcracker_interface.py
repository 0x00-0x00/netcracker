# coding:utf-8
from os import system
from subprocess import Popen, PIPE
from time import sleep
import os
import random
from shemutils.logger import Logger

# Static variables
DN = open(os.devnull, "w")
ERRLOG = open(os.devnull, "w")
OUTLOG = open(os.devnull, "w")
logger = Logger("INTERFACE")


def validate_mac(mac):
    """
    Takes a MAC string and validates it.
    :param mac:
    :return: 1 if success, 0 if not
    """
    octet = mac[0]
    if int("0x{0}".format(octet), 16) % 2 != 0:
        return 0
    else:
        return 1


def generate_mac(mac_size=6):
    mac = [hex(random.randint(1, 255)).strip("0x") for x in range(mac_size)]
    while not validate_mac(mac):
        mac = [hex(random.randint(1, 255)).strip("0x") for x in range(mac_size)]
    return ':'.join(mac)


class Interface:
    def __init__(self, interface):
        self.interface = interface

    def changeMac(self, mode):
        if not mode:
            command = "macchanger -r {0}".format(self.interface)
            logger.debug("Command issued: {0}".format(command))
            proc = Popen(command, shell=True, stdout=DN, stderr=DN)
            while proc.poll() is None:
                sleep(0.5)
            if proc.poll() == 0:
                return 0
            else:
                return -1
        else:
            command = "macchanger -p {0}".format(self.interface)
            proc = Popen(command, shell=True, stdout=DN, stderr=DN)
            while proc.poll() is None:
                sleep(0.5)
            if not proc.poll():
                return 0
            else:
                return -1

    def changeMode(self, mode):
        print(mode)
        if mode == "monitor":
            mode = "start"
        elif mode == "managed":
            mode = "stop"
        cmd = "airmon-ng {0} {1}".format(mode, self.interface)
        print(cmd)
        if system(cmd) != 0:
            return -1
        else:
            if mode == "start":
                self.interface += "mon"
                logger.info("Interface is now {0}".format(self.interface))
            else:
                self.interface = self.interface.replace("mon", "")
                logger.info("Interface is now {0}".format(self.interface))
            return 0

    def changePower(self, state):
        if system("ifconfig {0} {1}".format(self.interface, state)) != 0:
            return -1
        else:
            return 0
