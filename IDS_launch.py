#!/usr/bin/env python3.9

from subprocess import run
from time import sleep
import threading

script_path = "evil_twin_attack_detection.py"
python_command = "python3"

ap_mac = "18:02:ae:24:f0:ff"
client_mac = "e8:f7:91:9f:f0:a0"
broad_mac = "ff:ff:ff:ff:ff:ff"
launch_interval = 10  # launch interval in seconds after which a new instance of the script starts
thread_sleep_interval = 10  # how long is one probe interval
instances_launched = 0

while True:
    instances_launched += 1
    t = threading.Thread(target=run, args=([python_command, script_path, ap_mac, client_mac, broad_mac, str(instances_launched), str(thread_sleep_interval)],))
    t.start()
    sleep(launch_interval)

