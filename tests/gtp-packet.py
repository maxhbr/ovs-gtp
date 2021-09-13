#! /usr/bin/env python3
#  /vagrant/scripts/gtp-packet.py fd00::1 fd00::2 2001::1 2001::2 5555 p0
import time


from scapy.contrib.gtp import (
    GTP_U_Header,
    GTPEchoRequest,
    GTPPDUSessionContainer)
from scapy.all import *
import sys

no_of_args = 9

if len(sys.argv) != no_of_args:
    print("missing or more param: expected: %d given: %d" % (no_of_args, len(sys.argv)));
    exit()

out_src = sys.argv[1]
out_dst = sys.argv[2]
in_src = sys.argv[3]
in_dst = sys.argv[4]
in_port = sys.argv[5]
e_dev = sys.argv[6]
echo = sys.argv[7]
seq = sys.argv[8]

if out_src.count(':') >= 2:
    outer_ip_header = IPv6(src=out_src, dst=out_dst)
else:
    outer_ip_header = IP(src=out_src, dst=out_dst)

if in_src.count(':') >= 2:
    inner_ip_header = IPv6(src=in_src, dst=in_dst)
else:
    inner_ip_header = IP(src=in_src, dst=in_dst)

if str(echo) == 'True':
    pkt = Ether()/outer_ip_header/UDP(sport=2152,dport=2152)/GTP_U_Header(S=1,teid=0,seq=int(seq),next_ex=133)/GTPEchoRequest()
else:
    pkt = Ether()/outer_ip_header/UDP(sport=2152,dport=2152)/GTP_U_Header(S=1, teid=0,seq=int(seq),next_ex=133)/GTPPDUSessionContainer(type=1, QFI=6)/inner_ip_header/UDP(sport=int(in_port),dport=int(in_port))/Raw(load="Example Payload")

sendp(pkt, iface=e_dev)
