#! /usr/bin/env python

from __future__ import print_function
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from time import sleep
import os

"""
To-Do Items:
* HTML Reporting of discovered IP Addresses and Hostnames
* Graphing IP Address source and destinations  
* OS / Service discovery based on passive fingerprting (e.g. p0f)
* Menu / cmd-line argv usage setup
"""

def packetreader():
    """
    Parse the pcap file leveraging scapy to identify DNS hostnames.

    Returns
    -------
    string
        DNS hostname(s)
        Generic no hostnames found message 
    """
    pcap = 'sniff.pcap'
    pkts = readpcap(pcap)
    for p in pkts:
        if p.haslayer(DNS):
            if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                dnsname = p.qd.qname
            elif p.ancount > 0 and isinstance(p.an, DNSRR):
                dnsname = p.an.rdata
            else:
                print ("No hostnames found")

            print (dnsname)

# Global Counter
counter = 0

# Custom scapy function
def srcdst_action(packet):
    """
    Establish the scapy function to return IP source and destinations of sniffed packets.
    """
    global counter
    counter += 1
    return 'Packet #{}: {} ==> {}'.format(counter, packet[0][1].src, packet[0][1].dst)

# Setup sniffer
def main():
    """
    Main program that sets up the sniffer

    Be aware that any previous sniff.pcap is removed prior to running.
    After sniffing the specified packets using count wpcap writes out to sniff.pcap.
    After writing, packetreader analyzes the pcap and writes out to stdout the discovered hostnames.
    """
    try:
        os.remove('sniff.pcap')
    except OSError:
        pass
    print ('Discovered Hosts')
    # Edit the below count to adjust how many packets to sniff
    packets = sniff(filter="ip", prn=srcdst_action, count=100)
    wrpcap("sniff.pcap", packets)
    print ("~ Analyzing Hostname ~")
    packetreader()

if __name__ == "__main__":
    main()
