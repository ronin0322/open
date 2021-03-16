import scapy_http.http as HTTP

from scapy.all import *

from scapy.error import Scapy_Exception

 

count=0
map = {'192.168.1.100': '1', '192.168.1.200': '4', '192.168.1.103': '6','192.168.1.207': '8'}

def operation(src,dst):
	if dst in map and src in map:
		print 'ovs-ofctl add-flow vswitch0 "priority=3,in_port=1,actions=output:'+map[dst]+'"'
		os.system('ovs-ofctl add-flow vswitch0 "priority=3,in_port='+map[src]+',ip,nw_dst='+str(dst)+',actions=output:'+map[dst]+'"')
		os.system('ovs-ofctl add-flow vswitch0 "priority=3,in_port='+map[dst]+',ip,nw_dst='+str(src)+',actions=output:'+map[src]+'"')
		os.system('ovs-ofctl add-flow vswitch0 "priority=3,in_port='+map[src]+',arp,nw_dst='+str(dst)+',actions=output:'+map[dst]+'"')
		os.system('ovs-ofctl add-flow vswitch0 "priority=3,in_port='+map[dst]+',arp,nw_dst='+str(src)+',actions=output:'+map[src]+'"')

def pktTCP(pkt):

    global count

    count=count+1

    print count
    status1 = pkt.payload.name  # ARP
    status2 = pkt.payload.payload.name  # TCP or ICMP
    #if HTTP.HTTPRequest or HTTP.HTTPResponse in pkt:
    if status1 == 'IP':
    	#if status2 == 'ICMP':
         #   	print 'icmp '*10
          #  	pkt.show()
    	#else:
        	src=pkt[IP].src
        	#srcport=pkt[IP].sport
        	dst=pkt[IP].dst
        	#dstport=pkt[IP].dport
        	print src
        	#print srcport
        	print dst
        	#print dstport
        	#test=pkt[TCP].payload
        	#print test
        	operation(src,dst)
		if HTTP.HTTPRequest in pkt:
		    #print "HTTP Request:"
		    #print test
		    	print "=" * 10
			if HTTP.HTTPResponse in pkt:
			    print "HTTP Response:"
			    try:
				headers,body= str(test).split("\r\n\r\n", 1)
				print headers
			    except Exception,e:
				print e
			    print "=" * 10
    else:
    	if status1 == 'ARP':
    		print 'arp '*10
    		psrc=pkt[ARP].psrc
    		pdst=pkt[ARP].pdst
    		print psrc
    		print pdst
    		operation(psrc,pdst)
       
sniff(prn=pktTCP,iface='tap5_br')
#sniff(filter='arp or tcp',prn=pktTCP,iface='tap5_br')
