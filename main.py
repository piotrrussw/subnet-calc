#!/usr/bin/python
import ipaddress
import re
import sys
import socket


def is_valid_ip(ip_addr):
    octet_ip = ip_addr.split(".")
    int_octet_ip = [int(i) for i in octet_ip]
    if (len(int_octet_ip) == 4) and \
            (0 <= int_octet_ip[0] <= 255) and \
            (0 <= int_octet_ip[1] <= 255) and \
            (0 <= int_octet_ip[2] <= 255) and \
            (0 <= int_octet_ip[3] <= 255):
        return True
    else:
        print("Invalid IP, closing program... \n")
        exit(0)


def is_private_ip(ip_addr):
    pv_lo = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    pv_24 = re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    pv_20 = re.compile(r"^192\.168\.\d{1,3}.\d{1,3}$")
    pv_16 = re.compile(r"^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")
    res = pv_lo.match(ip_addr) or pv_24.match(ip_addr) or pv_20.match(ip_addr) or pv_16.match(ip_addr)
    return res is not None


def ip_to_binary(ip_addr):
    return ".".join(map(str, ["{0:08b}".format(int(x)) for x in ip_addr.split(".")]))


def get_address(ip_addr):
    return ipaddress.ip_network(ip_addr)


def get_network_class(ip_addr):
    return


def get_broadcast_address(ip_addr):
    return


arg = sys.argv
ip = ''
mask = ''

if len(arg) > 1:
    [ip, mask] = arg[1].split('/')
else:
    print('No ip address was passed, getting automatically...')
    ip = socket.gethostbyname(socket.getfqdn())

is_private = 'private' if is_private_ip(ip) else 'public'

if is_valid_ip(ip):
    print("\nThe entered ip address is: " + ip)
    print("Ip address in binary is: " + ip_to_binary(ip))
    print("The entered ip address is: " + is_private)
    print("The entered subnet mask is: " + mask)
