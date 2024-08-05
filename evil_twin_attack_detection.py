#!/usr/bin/env python3.9
from scapy.all import *
import time
import pygame
from time import time, sleep
from threading import *
from scapy.layers.dot11 import Dot11Deauth, RadioTap, Dot11Disas, Dot11Beacon, Dot11
from scapy.sendrecv import sniff, AsyncSniffer
import sys
pygame.mixer.init()
alarm_sound = pygame.mixer.Sound("alarm.mp3")

client_mac = "e8:f7:91:9f:f0:a0"
ap_mac = "18:02:ae:24:f0:ff"#9e:b8:bc:fd:29:e2" 
deauth_cnt: int = 0
disas_cnt: int = 0
evil_beacon: int =0
result: int=0

num = 10000

reason_code = []

ap_mac = sys.argv[1]
client_mac = sys.argv[2]
broad_mac = sys.argv[3]
instance_num = sys.argv[4]
thread_sleep_interval = int(sys.argv[5])
ssid ="diya"
iface = "wlan1"


def deauth_disassoc_callback(frame):  # counts malformed beacons
    global deauth_cnt, disas_cnt, r_flag,result
    if frame.haslayer(Dot11Deauth):
        deauth_cnt += 1
        dot11_layer = frame.getlayer(Dot11Deauth)
        reason_code.append(dot11_layer.reason)
    if frame.haslayer(Dot11Disas):
        disas_cnt += 1
        dot11_layer = frame.getlayer(Dot11Disas)
        reason_code.append(dot11_layer.reason)
    result = all(element == reason_code[0] for element in reason_code)
    if result:
        r_flag = True
    else:
        r_flag = False


deauth_sniffer = AsyncSniffer(iface=iface, count=num, prn=deauth_disassoc_callback, store=0, monitor=True)

def evil_twin_beacon(frame):
    global evil_beacon
    if frame.haslayer(Dot11Beacon):
        getssid = str(frame.info)
        ap_ssid = getssid[2:len(getssid) - 1]
        bssid = frame[Dot11].addr3
        #print(bssid,"\t",ap_mac,"\t",ssid,"\t",ap_ssid)
        if (bssid != ap_mac and ssid == ap_ssid):
                 evil_beacon += 1
                


evil_twin_sniffer = AsyncSniffer(iface=iface, count=num, prn=evil_twin_beacon, store=0, monitor=True)

deauth_sniffer.start()
evil_twin_sniffer.start()

def channel_switch():
    global channel_switch_sniffer

    def channel_switch_callback(frame):  # finds CSA beacons
        global cnt0
        if frame.haslayer(Dot11):
            b_addr = frame[Dot11].addr3
            if b_addr == ap_mac and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
                frame_elt = frame[Dot11Elt]
                while frame_elt:
                    if frame_elt.ID == 37:  # Extract Channel Switch Announcement Information Element
                        cnt0 += 1
                    frame_elt = frame_elt.payload

    channel_switch_sniffer = AsyncSniffer(iface=iface1, count=num, prn=channel_switch_callback, store=0, monitor=True)
    channel_switch_sniffer.start()
    

def play_alarm():
	pygame.mixer.init()
	alarm_sound = pygame.mixer.Sound("alarm.mp3")
	alarm_sound.play()
	pygame.time.wait(int(alarm_sound.get_length()) * 1000)
print("---------------------------------------------------------")
print(f"Probe interval number {instance_num} started")


sleep(thread_sleep_interval)

print(f"-----------Results of probe interval number {instance_num} started ----")
print("Deauth Count =", deauth_cnt)
print("Disass Count =", disas_cnt)
print("Evil-Twin-Beacons =", evil_beacon)
print("---------------------------------------------------------")
print("                 Final Decision                          ")
print("---------------------------------------------------------")

if ((deauth_cnt >= 10 or disas_cnt >= 10) and evil_beacon >=1 ) :
    #if cnt0>=1:
    	#print("Channel switch attack")
    print("Evil Twin Attack detected !!!!!!!!!")
    play_alarm()
else:
    print("No attack found")

