# coding:utf-8
from os import system
from subprocess import Popen, PIPE
from time import sleep
from shemutils import Logger
from netcracker.colors import *

import os
import random


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
    mac = ["%02x" % int(hex(random.randint(1, 255)).strip("0x"), 16) for x in range(mac_size)]
    while not validate_mac(mac):
        mac = ["%02x" % int(hex(random.randint(1, 255)).strip("0x"), 16) for x in range(mac_size)]
    return ':'.join(mac)


class Interface:
    def __init__(self, interface):
        self.interface = interface
        self.state = self._check_state()
        self.mode = self._check_mode()

    def _check_state(self):
        """
        Issues 'ifconfig' and check if interface is there.
        If an interface is not listed in 'ifconfig', it means that it is not in UP state, impliciting that
        it is in DOWN state.
        """
        proc = Popen("ifconfig", stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = proc.communicate()
        if self.interface in stdout:
            return 1
        else:
            return 0

    def _check_mode(self):
        """
        Issue a 'iwconfig INTERFACE' and get it's output. 
        If the word 'managed' is in output, means that the current interface is in 'Managed' mode.
        Yet, check the same way for the word 'monitor' meaning that the interface is in 'Monitor' mode.
        If neither words were caught, returns 0.
        """
        proc = Popen("iwconfig {0}".format(self.interface), shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()
        if "managed" in stdout.lower():
            return "managed"
        elif "monitor" in stdout.lower():
            return "monitor"
        else:
            logger.error("Could not get interface mode.")
            return 0

    def changeMac(self, mode):
        if self.mode is "monitor":
            self.changePower("down")
            self.changeMode("managed")

        if self.state is 1:
            self.changePower("down")

        if not mode:
            mac = generate_mac()
            logger.debug("Changing interface mac to {0} ...".format(mac))
            command = "ifconfig {0} hw ether {1}".format(self.interface, mac)
            #  logger.debug("Command issued: {0}".format(command))
            proc = Popen(command, shell=True, stdout=DN, stderr=DN)
            while proc.poll() is None:
                sleep(0.5)
            if not proc.poll():
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
