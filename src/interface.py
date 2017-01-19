# coding:utf-8
from os import system
from subprocess import Popen, PIPE
from time import sleep
import os
import random
from shemutils import Logger

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
            command = "ifconfig {0} hw ether {1}".format(self.interface, generate_mac())
            logger.debug("Command issued: {0}".format(command))
            proc = Popen(command, shell=True, stdout=DN, stderr=DN)
            while proc.poll() is None:
                sleep(0.5)
            if proc.poll() == 0:
                return 0
            else:
                return -1
        else:
            command = "ifconfig {0} hw ether $(ethtool -P {1} | awk '{print $3}')".format(self.interface,
                                                                                          self.interface)
            proc = Popen(command, shell=True, stdout=DN, stderr=DN)
            while proc.poll() is None:
                sleep(0.5)
            if not proc.poll():
                return 0
            else:
                return -1

    def changeMode(self, mode):
        if system("iwconfig %s mode %s" % (self.interface, mode)) != 0:
            return -1
        else:
            return 0

    def changePower(self, state):
        if system("ifconfig %s %s" % (self.interface, state)) != 0:
            return -1
        else:
            return 0
