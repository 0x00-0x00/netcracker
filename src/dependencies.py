
#  Arguments must be passed as dict, {"program name": "command to return 0", "program name2": "command2 to return 0"}

from shemutils import Logger
from subprocess import Popen

DN = open("/dev/null", "w")


class DepCheck(object):
    """
    Checks if external programs are installed in the system.
    """
    def __init__(self, deps):
        self.deps = deps
        self.state = None

    def _check(self):
        self.state = True
        for program in self.deps:
            if self._test(self.deps[program]):
                logger.error("Program '{0}' is not installed. Aborting.".format(program))
                self.state = False
                break

    @staticmethod
    def _test(q):
        p = Popen(q, shell=True, stdout=DN, stderr=DN)
        return p.poll()
