import threading
from threading import *
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP
import optparse
from time import sleep
import os


import webbrowser
# webbrowser.open("http://www.vulnweb.com/")
# webbrowser.open("http://info.cern.ch/")
# webbrowser.open("http://lushbrightfinebirds.neverssl.com/online")
# webbrowser.open("http://www.columbia.edu/~fdc/sample.html")


def arguments():
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog
    arguments = optparse.OptionParser()
    arguments.add_option("-i", "--interface", metavar='\b', dest="interface",
                         help="specify the interface the packets are flowing through")
    arguments.add_option("-s", "--secs", metavar='\b', dest="secs",
                         help="no of secs to sniff", default=20)
    values, options = arguments.parse_args()
    if not values.interface:
        arguments.error("give arguments\n[+]Help: python3 packet_sniffer.py -h")
    return values


def exitfunc():
    os._exit(0)


class network_analyzer():

    def __init__(self, interface):
        self.interface=interface
        self.sndips = []
        self.t = 0
        print("      src-ip                  dst-ip               visited")
        # print("      src-ip                  dst-ip               src-port         dst-port ")
        # print("|----------------------------------------------------------------------------|")
        # self.sniff(self.interface)
        # self.print_values(self.sndips)

    def start_sniff(self):
        self.sniff(self.interface)

    def start_print(self):
        self.print_values()

    def sniff(self,interface):
        scapy.sniff(iface=interface, store=False, prn=self.print_packet)

    def add_parameters(self,srcip, dstip):
        k = False
        self.t = self.t+1
        if self.t==1:
            self.sndips.append([srcip, dstip, 1])
        else:
            for i in range(len(self.sndips)):
                if self.sndips[i][0] == srcip and self.sndips[i][1] == dstip:
                    self.sndips[i][2] = self.sndips[i][2] + 1
                    k = True
            if not k:
                self.sndips.append([srcip, dstip, 1])

    def print_packet(self,pkt):
        try:
            if pkt.haslayer(http.HTTPRequest):
                # print("sniffed")
                # print("   " + pkt[IP].src + "            " + pkt[IP].dst + "            " + str(
                #     pkt[TCP].sport) + "             " + str(pkt[TCP].dport))
                self.add_parameters(pkt[IP].src, pkt[IP].dst)
                # print("|----------------------------------------------------------------------------|")
        except:
            pass

    def print_values(self):
        while True:
            for i in self.sndips:
                print("      " + str(i[0]) + "            " + str(i[1]) + "            " + str(i[2]))
            self.sndips = []
            print("|-------------------------------------------------------------|")
            sleep(5)


values = arguments()
ob1 = network_analyzer(values.interface)
Timer(int(values.secs), exitfunc).start()
threading.Thread(target=ob1.start_sniff).start()
threading.Thread(target=ob1.start_print).start()
