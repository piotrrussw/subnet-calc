#!/usr/bin/python
import re
import struct
import sys
import socket
import fcntl


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
    if not is_valid_ip(mask_addr):
        # Each mask looks like an IPv4 address and must pass the checks
        return False

    ip_mask_binary = ""
    ip_mask_binary = ip_mask_binary.join([bin(int(i))[2:] for i in mask_addr.split(".")])

    is_bit_zero = mask_addr[0] == "0"
    for bit in ip_mask_binary[1:]:
        if bit == "1" and is_bit_zero:
            return False

        if bit == "0":
            is_bit_zero = True

    return True


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


def netmask_to_cidr(net_mask):
    return str(sum([bin(int(bits)).count("1") for bits in net_mask.split(".")]))


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


def to_binary(ip_addr):
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
    first_octet = int(ip_addr.split(".")[0])

    if first_octet in range(0, 128):
        return "A"
    if first_octet in range(128, 192):
        return "B"
    if first_octet in range(192, 224):
        return "C"
    if first_octet in range(224, 240):
        return "D"
    if first_octet in range(240, 256):
        return "E"


def get_broadcast_address(ip_addr, subnet_mask):
    """

    :param ip_addr:
    :param subnet_mask:
    :return:
    """
    return ".".join(map(str, [i | m  # Apply the mask
                              for i, m in zip(map(int, ip_addr.split(".")),
                                              map(int, subnet_mask.split(".")))]))


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
    mask = cidr_to_netmask(mask)
else:
    print('No ip address was passed, getting automatically...')
    mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                        35099, struct.pack('256s', "lo"))[20:24])
    ip = socket.gethostbyname(socket.getfqdn())

is_private = 'private' if is_private_ip(ip) else 'public'

if is_valid_ip(ip) and is_valid_mask(mask):
    print("\nThe entered ip address is: " + ip)
    print("Ip address in binary is: " + to_binary(ip))
    print("The entered ip address is: " + is_private)
    print("The entered mask cidr is: " + netmask_to_cidr(mask))
    print("The entered mask is: " + mask)
    print("The entered mask binary is: " + to_binary(mask))
    print("The entered network address is: " + get_network_address(ip, mask))
    print("The entered network class is: " + get_network_class(ip))
    print("The entered broadcast address is: " + get_broadcast_address(ip, mask))
