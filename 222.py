import threading
from threading import *
from scapy.layers.inet import *
from  scapy.layers.l2 import *
import scapy.all as scapy
import optparse
from time import sleep
import os
import netifaces as ni




'''
websites reffered : https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml -- Ether codes
                  : https://scapy.readthedocs.io/en/latest/api/scapy.layers.html -- 
'''


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
        self.local_pri_ip = self.get_private_ip(self.interface)
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

    def get_private_ip(self, interface):
        return ni.ifaddresses(interface).get(2)[0].get('addr')

    def sniff(self,interface):
        scapy.sniff(iface=interface, store=False, prn=self.print_packet)

    def add_parameters(self,srcip, dstip, type):
        k = False
        self.t = self.t+1
        if self.t==1:
            self.sndips.append([srcip, dstip, 1, type])
        else:
            for i in range(len(self.sndips)):
                if self.sndips[i][0] == srcip and self.sndips[i][1] == dstip:
                    self.sndips[i][2] = self.sndips[i][2] + 1
                    k = True
            if not k:
                self.sndips.append([srcip, dstip, 1, type])

    def print_packet(self,pkt):
        global type
        try:
            if Ether in pkt:
                if ARP in pkt:
                    if pkt[ARP].op == 1:
                        status = "who has"
                    elif pkt[ARP].op == 2:
                        status = "is at"
                    else:
                        status = "ARP call not found"
                    type = "ARP => {a}".format(a=status)
                    self.add_parameters(pkt[ARP].psrc, pkt[ARP].pdst, type)
                elif IP in pkt:
                    if pkt[IP].dst == self.local_pri_ip:
                        pass
                    elif ICMP in pkt:
                        if pkt[ICMP].type == 8:
                            type = "ICMP => request"
                        if pkt[ICMP].type == 0:
                            type = "ICMP => reply"
                    elif pkt[TCP].dport == 443:
                        type = "https"
                    elif pkt[TCP].dport == 80:
                        type = "http"
                    else:
                        type = pkt[TCP].dport
                    self.add_parameters(pkt[IP].src, pkt[IP].dst, type)
                else:
                    pass
        except:
            pass

    def print_values(self):
        while True:
            for i in self.sndips:
                print("      " + str(i[0]) + "            " + str(i[1]) + "            " + str(i[2])+"             "+str(i[3]))
            self.sndips = []
            print("|-------------------------------------------------------------|")
            sleep(5)


values = arguments()
ob1 = network_analyzer(values.interface)
Timer(int(values.secs)+1, exitfunc).start()
threading.Thread(target=ob1.start_sniff).start()
threading.Thread(target=ob1.start_print).start()
