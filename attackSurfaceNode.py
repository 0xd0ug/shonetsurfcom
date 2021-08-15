from abc import ABC, abstractmethod
from ipaddress import ip_address
import Levenshtein

counter = 0

global portweight
global prefixweight

class AttackSurfaceNode(ABC):

    @abstractmethod
    def __init__(self):
        global counter
        self.counter = counter
        counter += 1

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass


class Service(AttackSurfaceNode):
    def __init__(self, ip: str, port: int, service: str, banner: str, servindex: int):
        super().__init__()
        self.ip = ip_address(ip)
        self.port = port
        self.service = service
        self.banner = banner
        self.servindex = servindex

    def similarity(self, other, portweight=0.5, prefixweight=.05):
        if self.service != '' and other.service != '':
            #portSim = Levenshtein.jaro(self.service, other.service)
            if self.service == other.service:
                portSim = 1
            else:
                portSim = 0
        else:
            if self.port == other.port:
                portSim = 1
            else:
                portSim = 0
        if self.banner == '' and other.banner == '':
            sim = portSim
        else:
            #bannerSim = Levenshtein.jaro_winkler(self.banner, other.banner, prefixweight)
            bannerSim = Levenshtein.jaro(self.banner, other.banner)
            sim = (bannerSim * (1-portweight) + portSim * portweight)
        return sim

    def __str__(self):
        output = str(self.ip) + "," + str(self.port) + ',' + self.service + ',' + self.banner[0:90].replace(',', ';')
        if len(self.banner) > 90:
            output += '...'
        return output

    def __eq__(self, other):
        return (self.ip == other.ip) and (self.port == other.port) and (self.banner == other.banner)

    def __hash__(self):
        return hash((self.ip, self.port))
