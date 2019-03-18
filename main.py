#!/usr/bin/python
import ipaddress
import re
import sys
import socket


def is_valid_ip(ip_addr):
    """

    :param ip_addr:
    :return:
    """
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


def is_valid_mask(mask_addr):
    """

    :param mask_addr:
    :return:
    """
    int_mask = int(mask_addr)
    if 1 <= int_mask <= 30:
        return True
    else:
        return False


def cidr_to_netmask(cidr):
    """

    :param cidr:
    :return:
    """
    cidr = int(cidr)
    mask_addr = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (str((0xff000000 & mask_addr) >> 24) + '.' +
            str((0x00ff0000 & mask_addr) >> 16) + '.' +
            str((0x0000ff00 & mask_addr) >> 8) + '.' +
            str((0x000000ff & mask_addr)))


def is_private_ip(ip_addr):
    """

    :param ip_addr:
    :return:
    """
    pv_lo = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    pv_24 = re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    pv_20 = re.compile(r"^192\.168\.\d{1,3}.\d{1,3}$")
    pv_16 = re.compile(r"^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")
    res = pv_lo.match(ip_addr) or pv_24.match(ip_addr) or pv_20.match(ip_addr) or pv_16.match(ip_addr)
    return res is not None


def ip_to_binary(ip_addr):
    """

    :param ip_addr:
    :return:
    """
    return ".".join(map(str, ["{0:08b}".format(int(x)) for x in ip_addr.split(".")]))


def get_network_address(ip_addr, subnet_mask):
    """

    :param ip_addr:
    :param subnet_mask:
    :return:
    """
    return ".".join(map(str, [i & m  # Apply the mask
                              for i, m in zip(map(int, ip_addr.split(".")),
                                              map(int, subnet_mask.split(".")))]))


def get_network_class(ip_addr):
    return


def get_broadcast_address(ip_addr):
    return


def get_primary_host(ip_addr):
    return


def get_last_host(ip_addr):
    return


def get_maximum_hosts(ip_addr):
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

if is_valid_ip(ip) and is_valid_mask(mask):
    print("\nThe entered ip address is: " + ip)
    print("Ip address in binary is: " + ip_to_binary(ip))
    print("The entered ip address is: " + is_private)
    print("The entered mask cidr is: " + mask)
    print("The entered mask is: " + cidr_to_netmask(mask))
    print("The entered network address is: " + get_network_address(ip, mask))
