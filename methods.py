import re


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
    return ".".join(map(str, [(i | ~m) & 0xff  # Apply the mask
                              for i, m in zip(map(int, ip_addr.split(".")),
                                              map(int, subnet_mask.split(".")))]))


def get_min_host(net_address):
    octet_net_address = net_address.split(".")
    octet_net_address[3] = str(int(octet_net_address[3]) + 1)
    return ".".join(octet_net_address)


def get_max_host(broadcast_addr):
    octet_broadcast_address = broadcast_addr.split(".")
    octet_broadcast_address[3] = str(int(octet_broadcast_address[3]) - 1)
    return ".".join(octet_broadcast_address)


def get_maximum_hosts(sub_mask):
    no_zeros = to_binary(sub_mask).count("0")
    return str(2 ** abs(no_zeros) -2)
