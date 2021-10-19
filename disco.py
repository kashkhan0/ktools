"""
Implements GigE Vision GVCP Discovery Protocol (Controller Side)

Enables discovery of GigE Vision camereras.

Copyright (C) 2019 Cogniac Corporation
All rights reserved.
"""

import socket
from time import time
import select
import struct
from collections import OrderedDict
import binascii

GVCP_PORT = 3956


def parse_gvcp_discovery_ack(data):
    """
    parse GVCP discovery ACK and return a dictionary with keys/data like this:

    spec_version_major: 1
    spec_version_minor: 1
           device_mode: 2147483649
     IP_config_options: 7
     IP_config_current: 6
            current_IP: 192.168.1.184
   current_subnet_mask: 255.255.255.0
       default_gateway: 192.168.1.1
     manufacturer_name: Basler
            model_name: acA3800-10gm
        device_version: 106702-13
     manufacturer_info: none
         serial_number: 22493823
     user_defined_name:
                   mac: 00:30:53:26:0d:7f
    """

    # define discovery ack packet using ordered dict mapping between field names and python struct decode format
    ack_struct = OrderedDict()
    ack_struct['status'] = 'H'
    ack_struct['answer'] = 'H'
    ack_struct['length'] = 'H'
    ack_struct['ack_id'] = 'H'
    ack_struct['spec_version_major'] = "H"
    ack_struct['spec_version_minor'] = "H"
    ack_struct['device_mode'] = "I"
    ack_struct['reserved1'] = "H"
    ack_struct['mac0'] = "B"
    ack_struct['mac1'] = "B"
    ack_struct['mac2'] = "B"
    ack_struct['mac3'] = "B"
    ack_struct['mac4'] = "B"
    ack_struct['mac5'] = "B"
    ack_struct['IP_config_options'] = "I"
    ack_struct['IP_config_current'] = "I"
    ack_struct['reserved2'] = "I"
    ack_struct['reserved3'] = "I"
    ack_struct['reserved4'] = "I"
    ack_struct['current_IP'] = "4s"
    ack_struct['reserved5'] = "I"
    ack_struct['reserved6'] = "I"
    ack_struct['reserved7'] = "I"
    ack_struct['current_subnet_mask'] = "4s"
    ack_struct['reserved8'] = "I"
    ack_struct['reserved9'] = "I"
    ack_struct['reserved10'] = "I"
    ack_struct['default_gateway'] = "4s"
    ack_struct['manufacturer_name'] = "32s"
    ack_struct['model_name'] = "32s"
    ack_struct['device_version'] = "32s"
    ack_struct['manufacturer_info'] = "48s"
    ack_struct['serial_number'] = "16s"
    ack_struct['user_defined_name'] = "16s"

    # compile the ordered dict into the python struct format string
    struct_format = "!"
    for sformat in ack_struct.values():
        struct_format += sformat

    ack_decoded = OrderedDict()
    ACK_LEN = 256   # data should be 256 bytes -- ignore any additional data that it sent
    for key, result in zip(ack_struct.keys(), struct.unpack(struct_format, data[:ACK_LEN])):
        if 'reserved' in key: continue  # ignore reserved fields
        ack_decoded[key] = result

    # compose sane-looking mac field
    ack_decoded['mac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % (ack_decoded['mac0'],
                                                            ack_decoded['mac1'],
                                                            ack_decoded['mac2'],
                                                            ack_decoded['mac3'],
                                                            ack_decoded['mac4'],
                                                            ack_decoded['mac5'])

    # remove useless field before returning dict
    for k in ['mac0','mac1','mac2','mac3','mac4','mac5','status', 'length', 'ack_id', 'answer']:
        del ack_decoded[k]

    # convert IP addresses to strings
    for k in ['current_IP', 'current_subnet_mask', 'default_gateway']:
        ack_decoded[k] = socket.inet_ntoa(ack_decoded[k])

    # strip training 0x00 from string fields
    for k in ['model_name', 'manufacturer_name', 'serial_number', 'user_defined_name']:
        ack_decoded[k] = ack_decoded[k].rstrip(b'\0')

    # ensure all strings are unicode otherwise this can lead to exceptions during upload
    for key, value in ack_decoded.items():
        if isinstance(value, str):
            ack_decoded[key] = value

    return ack_decoded


def gvcp_discovery_if(interface="", timeout_seconds=0.3):
    """
    perform GVCP discovery and return a list of device dictionaries (one for each discovered camera) like:

    spec_version_major: 1
    spec_version_minor: 1
           device_mode: 2147483649
     IP_config_options: 7
     IP_config_current: 6
            current_IP: 192.168.1.184
   current_subnet_mask: 255.255.255.0
       default_gateway: 192.168.1.1
     manufacturer_name: Basler
            model_name: acA3800-10gm
        device_version: 106702-13
     manufacturer_info: none
         serial_number: 22493823
     user_defined_name:
                   mac: 00:30:53:26:0d:7f
             source_IP: 192.168.1.184

    The source_IP is the IP address from which we received the ACK message whereas the current_IP
    is the device's self-reported IP from the discovery ACK message.
    """
    # send broadcast Discovery packet to GVCP UDP port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if interface:
        sock.setsockopt(socket.SOL_SOCKET, 25, interface + '\0')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 2)
    # sock.sendto("\x42\x19\x00\x02\x00\x00\xff\xff".encode(), ("255.255.255.255", GVCP_PORT))
    strMsg = "420100020000ffff"
    msg = binascii.unhexlify(strMsg)
    sock.sendto(msg, ("172.27.8.12", GVCP_PORT))
    # sock.sendto("\x42\x19\x00\x02\x00\x00\xff\xff".encode(), ("192.168.0.102", GVCP_PORT))

    # read the replies for up to timeout seconds
    sock.setblocking(0)
    print("oo", dir(sock))
    t0 = time()
    rxlist = []   # list of replies
    while (time() - t0 < timeout_seconds):
        print("oo", timeout_seconds)
        ready = select.select([sock], [], [], time() - t0)
        if ready[0]:
            data, address = sock.recvfrom(512)
            print("oo=", address )
            print("oo=", binascii.hexlify(data) )
            n = 8
            chunks = []

            i = 0
            while i < len(data):
                ee = data[i:i+n]
                print(i,ee)
                i += n

            rxlist.append((data, address))

    # parse out replies for each device
    devices = []
    for data, address in rxlist:
        ack = parse_gvcp_discovery_ack(data)
        ack['source_IP'] = address[0]
        devices.append(ack)

    return devices   # return list of dictionaries of per-device replies


def gvcp_discovery(ifaces, timeout_seconds=0.3):
    devices = list()
    for iface in ifaces:
        if_devs = gvcp_discovery_if(iface, timeout_seconds)
        devices.extend(if_devs)
    return devices


def gvcp2t(interface="", timeout_seconds=0.3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if interface:
        sock.setsockopt(socket.SOL_SOCKET, 25, interface + '\0')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 2)
    # sock.sendto("\x42\x19\x00\x02\x00\x00\xff\xff".encode(), ("255.255.255.255", GVCP_PORT))
    strMsg = "420100020000ffff"
    msg = binascii.unhexlify(strMsg)
    sock.sendto(msg, ("172.27.8.12", GVCP_PORT))
    sock.setblocking(0)
    print("oo", dir(sock))
    t0 = time()
    rxlist = []   # list of replies
    while (time() - t0 < timeout_seconds):
        print("oo", timeout_seconds)
        ready = select.select([sock], [], [], time() - t0)
        if ready[0]:
            data, address = sock.recvfrom(512)
            print("oo=", address )
            print("oo=", binascii.hexlify(data) )
            n = 8
            chunks = []

            rxlist.append((data, address))

    for r in rxlist:
        print("rx", r[1])


awa = "0000000300f8ffff0000000000000000000000000000000000000000000000000000000000000000000000007f0000010000000000000000000000000000000000000000000000000000000000000000417261766973000000000000000000000000000000000000000000000000000046616b6500000000000000000000000000000000000000000000000000000000302e382e313700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004756303100000000000000000000000000000000000000000000000000000000"


def gvcp2(interface="", timeout_seconds=0.3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if interface:
        sock.setsockopt(socket.SOL_SOCKET, 25, interface + '\0')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 2)
    strMsg = "420100020000ffff"
    msg = binascii.unhexlify(strMsg)
    #data, a2 = sendrecv(sock,"255.255.255.255", msg)
    #159.203.217.54
    bc = "255.255.255.255"
    # ip = "127.0.0.1"
   

    (data, address) = sendrecv(sock, "255.255.255.255", "420100020000ffff")


    # sendrecv(sock, "255.255.255.255", "420100020000ffff")
    print(f"recv {address[0]}")
    ip = address[0]
    reqs = [ 
        "420100840008ff150000020000000200",
        "420100840008ff160001000000000200", 
        "420100840008ff170001020000000200", 
        "420100840008ff180001040000000200"
        ]
    for r in reqs:
        sendrecv(sock, ip, r)

    # sendrecv(sock, ip, "420100840008ff150000020000000200")
    # sendrecv(sock, ip, "420100840008ff160001000000000200")
    # sendrecv(sock, ip, "420100840008ff170001020000000200")
    # sendrecv(sock, ip, "420100840008ff180001040000000200")

def sendto(sock,ip, msg):
    print("sendto", msg )
    sock.sendto(binascii.unhexlify(msg), (ip, GVCP_PORT))
    t0 = time()
    sock.setblocking(0)
    rxlist = []   # list of replies
    while (time() - t0 < 0.5):
        ready = select.select([sock], [], [], time() - t0)
        if ready[0]:
            data, address = sock.recvfrom(1500)
            print("sendto recv address", address,binascii.hexlify(data))
            return (data, address)
   



def sendrecv(sock,ip, msg):
    print("sendrecv to", msg )
    sock.sendto(binascii.unhexlify(msg), (ip, GVCP_PORT))
    sock.setblocking(0)
    t0 = time()
    rxlist = []   # list of replies
    while (time() - t0 < 0.5):
        ready = select.select([sock], [], [], time() - t0)
        if ready[0]:
            data, address = sock.recvfrom(1500)
            print("sendrecv address", address, binascii.hexlify(data))
            return (data, address)


if __name__ == "__main__":
    gvcp2()

    quit()
    dd = parse_gvcp_discovery_ack(binascii.unhexlify(awa))
    print(dd)
    quit()
    devices = gvcp_discovery_if()
    for device in devices:
        for key, value in device.iteritems():
            print (key,":", value)
    # parse_gvcp_discovery_ack("hello")