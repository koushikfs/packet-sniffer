import scapy.all as scapy
from scapy.layers import http
import optparse


def arguments():
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog
    arguments = optparse.OptionParser(
        epilog="\nhow to use ?\n  1) start arp-spoofer\n  2) run this script\n\nThat's it the sniffing will be started\n")
    arguments.add_option("-i", "--interface", metavar='\b', dest="interface",
                         help="specify the interface the packets are flowing through")
    values, options = arguments.parse_args()
    if not values.interface:
        arguments.error("give arguments\n[+]Help: python3 packet_sniffer.py -h")
    return values


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=print_packet)


def print_packet(pkt):
    src="!"
    dst="!!"
    src_port="*"
    dst_port="**"
    try:
        IP= "IP"
        TCP = "TCP"
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        print(src,dst)
        print(src_port, dst_port)
        print("+++++++++++++++++++++++++++++++=")
    except UnicodeDecodeError:
        pass


values = arguments()
sniff(values.interface)
