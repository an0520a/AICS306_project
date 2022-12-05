import ctypes
from ctypes import wintypes
from windows_h import *

#define PCAP_ERRBUF_SIZE 256
PCAP_ERRBUF_SIZE = 256

#define PCAP_SRC_IF_STRING "rpcap://"
PCAP_SRC_IF_STRING = ctypes.c_char_p(b"rpcap://")

#define PCAP_OPENFLAG_PROMISCUOUS		0x00000001
PCAP_OPENFLAG_PROMISCUOUS = 0x00000001

bpf_u_int32 = ctypes.c_uint

class pcap_addr(ctypes.Structure):
    pass
pcap_addr._fields_ = [("next", ctypes.POINTER(pcap_addr)),
                      ("addr", ctypes.POINTER(sockaddr)),
                      ("netmask", ctypes.POINTER(sockaddr)),
                      ("broadaddr", ctypes.POINTER(sockaddr)),
                      ("dstaddr", ctypes.POINTER(sockaddr))]

class pcap_if_t(ctypes.Structure):
    pass
pcap_if_t._fields_ = [("next", ctypes.POINTER(pcap_if_t)),
                      ("name", ctypes.c_char_p),
                      ("description", ctypes.c_char_p),
                      ("addresses", ctypes.POINTER(pcap_addr)),
                      ("flags", bpf_u_int32)]

pcap_if = pcap_if_t

class pcap_t(ctypes.Structure):
    pass
pcap = pcap_t

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval),
                ("caplen", bpf_u_int32),
                ("len", bpf_u_int32)]

class pcap_dumper_t(ctypes.Structure):
    pass
pcap_dumper = pcap_dumper_t