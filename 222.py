import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP
import optparse
import webbrowser

sndips = []
t = 0


def arguments():
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog
    arguments = optparse.OptionParser()
    arguments.add_option("-i", "--interface", metavar='\b', dest="interface",
                         help="specify the interface the packets are flowing through")
    values, options = arguments.parse_args()
    if not values.interface:
        arguments.error("give arguments\n[+]Help: python3 packet_sniffer.py -h")
    return values


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=print_packet)


def add_parameters(srcip, dstip):
    global t
    global sndips
    t = t+1
    if t==1:
        sndips.append([srcip, dstip, 0])
    else:
        for i in range(len(sndips)):
            if sndips[i][0] == srcip and sndips[i][1] == dstip:
                sndips[i][2] = sndips[i][2] + 1
            else:
                sndips.append([srcip, dstip, 1])


def print_packet(pkt):
    try:
        if pkt.haslayer(http.HTTPRequest):
            print("   " + pkt[IP].src + "            " + pkt[IP].dst + "            " + str(
                pkt[TCP].sport) + "             " + str(pkt[TCP].dport))
            add_parameters(pkt[IP].src, pkt[IP].dst)
            print("|----------------------------------------------------------------------------|")
    except:
        pass

values = arguments()
print("      src-ip                  dst-ip               src-port         dst-port ")
print("|----------------------------------------------------------------------------|")
webbrowser.open("http://www.vulnweb.com/")
webbrowser.open("http://info.cern.ch/")
webbrowser.open("http://lushbrightfinebirds.neverssl.com/online")
webbrowser.open("http://www.columbia.edu/~fdc/sample.html")
sniff(values.interface)
print("      src-ip                  dst-ip               visited")
for i in sndips:
    print("|-----------------------------------------------------|")
    print("      "+str(i[0])+"            "+str(i[1])+"            "+str(i[2]))