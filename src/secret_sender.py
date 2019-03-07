#!/usr/bin/env python2

# Credits: Adam Doupe, 2018

import argparse
import sys
import enum
import random
import string

from scapy.all import *

class MessageType(enum.Enum):
    ICMP = 0
    TCP = 1

def send_message(ip_address, interface, message_type, message):
    uid = random.choice(string.ascii_letters)
    count = 0

    if len(message) > 255:
        return;

    if message_type == MessageType.ICMP:
        for m in message:
            id_field = int((m+uid).encode("hex"), 16)
            send(IP(id=id_field, frag=count, dst=ip_address)/ICMP(), iface=interface)
            count += 1
        id_field = ord(uid)
        count = count | 0x1000
        send(IP(id=id_field, frag=count, dst=ip_address)/ICMP(), iface=interface)

    elif message_type == MessageType.TCP:
        for m in message:
            id_field = int((m+uid).encode("hex"), 16)
            send(IP(id=id_field, frag=count, dst=ip_address)/TCP(dport=80), iface=interface)
            count += 1
        id_field = ord(uid)
        count = count | 0x1000
        send(IP(id=id_field, frag=count, dst=ip_address)/TCP(dport=80), iface=interface)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="secret_sender")
    parser.add_argument("ip_address", type=str, help="destination IP address")
    parser.add_argument("interface", type=str, help="interface to send the message")
    parser.add_argument("type", type=int, help="type of message to send, 0 for ICMP echo, 1 for TCP SYN packet")
    parser.add_argument("message", type=str, help="the message to be sent")

    args = parser.parse_args()

    message_type = None

    if args.type == 0:
        message_type = MessageType.ICMP
    elif args.type == 1:
        message_type = MessageType.TCP
    else:
        sys.exit(-1)

    send_message(args.ip_address, args.interface, message_type, args.message)