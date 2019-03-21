#!/usr/bin/python
import os
import struct
import sys
import socket
import fcntl
from methods import *

arg = sys.argv
ip = ''
mask = ''

if len(arg) > 1:
    [ip, mask] = arg[1].split('/')
    mask = cidr_to_netmask(mask)
else:
    print('No ip address was passed, getting automatically...')
    ip = socket.gethostbyname(socket.getfqdn())
    mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                        35099, struct.pack('256s', "lo"))[20:24])

if is_valid_ip(ip) and is_valid_mask(mask):
    binary_ip = to_binary(ip)
    is_private = 'private' if is_private_ip(ip) else 'public'
    cidr_mask = netmask_to_cidr(mask)
    binary_mask = to_binary(mask)
    network_address = get_network_address(ip, mask)
    binary_network_address = to_binary(network_address)
    network_class = get_network_class(ip)
    broadcast_address = get_broadcast_address(ip, mask)
    binary_broadcast_address = to_binary(broadcast_address)
    maximum_hosts = get_maximum_hosts(mask)
    min_host = get_min_host(network_address)
    max_host = get_max_host(broadcast_address)

    text_file = open("data.txt", "w")
    text_file.write("The entered ip address is: " + ip + "\n")
    text_file.write("Binary IP: " + binary_ip + "\n")
    text_file.write("The entered ip address is: " + is_private + "\n")
    text_file.write("The entered mask cidr is: " + cidr_mask + "\n")
    text_file.write("The entered mask is: " + mask + "\n")
    text_file.write("The entered mask binary is: " + binary_mask + "\n")
    text_file.write("The entered network address is: " + network_address + "\n")
    text_file.write("The entered network address binary is: " + binary_network_address + "\n")
    text_file.write("The entered network class is: " + network_class + "\n")
    text_file.write("The entered broadcast address is: " + broadcast_address + "\n")
    text_file.write("The entered broadcast address binary is: " + binary_broadcast_address + "\n")
    text_file.write("The maximum number of hosts is: " + maximum_hosts + "\n")
    text_file.write("The min host is: " + min_host + "\n")
    text_file.write("The min host is: " + max_host + "\n")
    text_file.close()

    print("\nThe entered ip address is: " + ip)
    print("Ip address in binary is: " + binary_ip)
    print("The entered ip address is: " + is_private)
    print("The entered mask cidr is: " + cidr_mask)
    print("The entered mask is: " + mask)
    print("The entered mask binary is: " + binary_mask)
    print("The entered network address is: " + network_address)
    print("The entered network address binary is: " + binary_network_address)
    print("The entered network class is: " + network_class)
    print("The entered broadcast address is: " + broadcast_address)
    print("The entered broadcast address binary is: " + binary_broadcast_address)
    print("The maximum number of hosts is: " + maximum_hosts)
    print("The min host is: " + min_host)
    print("The min host is: " + max_host)

    if not len(arg) > 1 or ip == network_address or ip == broadcast_address:
        print("\n PING?")
        pressed = raw_input("Press Y or N\n")

        if pressed == 'Y':
            response = os.system("ping -c 1 " + ip)
            if response == 0:
                print(ip + ", is up!")
            else:
                print(ip + ", is down!")
        else:
            print("Thank you")

    exit(0)
