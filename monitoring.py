import sys
from scapy.all import *


probe = set()

def PacketHandler(packet):
    if packet.haslayer(Dot11ProbeReq):
        if packet.info:
            data = packet.addr2 + "#####" + packet.info.decode()
            if data not in probe:
                probe.add(data)
                client, ssid = data.split('#####')
                print("#########################################")
                print(str(client) + "\t" + str(ssid))
    else:
        pass

sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=PacketHandler)
