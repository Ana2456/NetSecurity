from scapy.all import *


#a=sniff(count=10)

#a.nsummary()
target='www.target.com/30'
ip = IP(dst=target)


#conf.verb = 0
#p = IP(dst="github.com")/TCP()
#r = sr1(p)
#print(r.summary())

#send(IP(dst="1.2.3.4")/TCP(dport=502, options=[("MSS", 0)]))
#ans = sr([IP(dst="8.8.8.8", ttl=(1, 8), options=IPOption_RR())/ICMP(seq=RandShort()), IP(dst="8.8.8.8", ttl=(1, 8), options=IPOption_Traceroute())/ICMP(seq=RandShort()), IP(dst="8.8.8.8", ttl=(1, 8))/ICMP(seq=RandShort())], verbose=False, timeout=3)[0]
#ans.make_table(lambda x, y: (", ".join(z.summary() for z in x[IP].options) or '-', x[IP].ttl, y.sprintf("%IP.src% %ICMP.type%")))

SYN = TCP(sport=1024, dport=80, flags='S', seq=12345)
packet = ip/SYN
SYNACK = sr1(packet)
ack = SYNACK.seq + 1
print(SYNACK.ack)
print(ack)

packet = Ether()/IP()/TCP()
ls(packet)

