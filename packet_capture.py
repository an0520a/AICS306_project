import ctypes
from npcap_h import *

wpcapdll : ctypes.CDLL

def packet_capture(interface_name : str, pcap_file_name : str = "tmp_pcap.pcap"):
    error_buf = (ctypes.c_char * PCAP_ERRBUF_SIZE)()
    wpcapdll.pcap_open.restype = ctypes.POINTER(pcap_t)
    pcap_device_handle = wpcapdll.pcap_open(interface_name.encode("UTF-8"), 65536, 0, None, error_buf)
    pcap_file = ctypes.POINTER(pcap_dumper_t)()

    if pcap_device_handle:
        pass
    else:
        print("Unable to open the adapter. {} is not supported by Npcap\n".format(interface_name))
        print(error_buf.decode("UTF-8"))
        exit(1)

    wpcapdll.pcap_dump_open.restype = ctypes.POINTER(pcap_dumper_t)
    pcap_file = wpcapdll.pcap_dump_open(pcap_device_handle, pcap_file_name.encode("UTF-8"))

    callback_func_type = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(pcap_pkthdr), ctypes.POINTER(ctypes.c_ubyte))
    callback_func = callback_func_type(py_packet_handler)

    wpcapdll.pcap_loop(pcap_device_handle, 0, callback_func, ctypes.cast(pcap_file, ctypes.POINTER(ctypes.c_ubyte)))

    wpcapdll.pcap_close(pcap_device_handle)


def py_packet_handler(dumpfile : ctypes.POINTER(ctypes.c_ubyte), header : ctypes.POINTER(pcap_pkthdr), pkt_data : ctypes.POINTER(ctypes.c_ubyte)):
    wpcapdll.pcap_dump(dumpfile, header, pkt_data)

def main():
        global wpcapdll
        wpcapdll = ctypes.CDLL(WPCAP_DLL_PATH)