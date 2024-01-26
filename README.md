# Stageless-PING-C2-implant
This is a simple python script that listens on PING (icmp) protocol and execute OS commands from the C2.
Currently only tested on Ubuntu 22 LTS.

Make sure to change the Server IP in the client script before moving it.

Dependencies:
- Ubuntu Based OS
- Python3.x
    $ sudo apt install python3
- Scapy python library
    $ pip install scapy