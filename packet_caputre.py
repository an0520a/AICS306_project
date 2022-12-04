import ctypes
from ctypes import wintypes
from ctypes import windll
import win32con
import win32api
import re

#define ANY_SIZE 1
ANY_SIZE = 1

#define AF_INET 2
#define AF_INET6 23
AF_INET = 2
AF_INET6 = 23

# typedef enum _TCP_TABLE_CLASS {
#   TCP_TABLE_BASIC_LISTENER,
#   TCP_TABLE_BASIC_CONNECTIONS,
#   TCP_TABLE_BASIC_ALL,
#   TCP_TABLE_OWNER_PID_LISTENER,
#   TCP_TABLE_OWNER_PID_CONNECTIONS,
#   TCP_TABLE_OWNER_PID_ALL,
#   TCP_TABLE_OWNER_MODULE_LISTENER,
#   TCP_TABLE_OWNER_MODULE_CONNECTIONS,
#   TCP_TABLE_OWNER_MODULE_ALL
# } TCP_TABLE_CLASS, *PTCP_TABLE_CLASS;
TCP_TABLE_BASIC_LISTENER = 0
TCP_TABLE_BASIC_CONNECTIONS = 1
TCP_TABLE_BASIC_ALL = 2
TCP_TABLE_OWNER_PID_LISTENER = 3
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
TCP_TABLE_OWNER_PID_ALL = 5
TCP_TABLE_OWNER_MODULE_LISTENER = 6
TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
TCP_TABLE_OWNER_MODULE_ALL = 8

# typedef enum _UDP_TABLE_CLASS {
#   UDP_TABLE_BASIC,
#   UDP_TABLE_OWNER_PID,
#   UDP_TABLE_OWNER_MODULE
# } UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;
UDP_TABLE_BASIC = 0
UDP_TABLE_OWNER_PID = 1
UDP_TABLE_OWNER_MODULE = 2

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
IPPROTO_TCP = 6
IPPROTO_UDP = 17

#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
ERROR_SUCCESS = 0
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122

#DWORD_PTR과 UNLONG_PTR은 32비트인지, 64비트인지의 여부에 따라 크기가 다름. 
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
    ULONG_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong
    ULONG_PTR = ctypes.c_ulong

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD),
                ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD),
                ("table", MIB_TCPROW_OWNER_PID * ANY_SIZE)]

class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte),
                ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("ucRemoteAddr", ctypes.c_ubyte),
                ("dwRemoteScopeId", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD),
                ("dwState", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]

class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD),
                ("table", MIB_TCP6ROW_OWNER_PID * ANY_SIZE)]

class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]

class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD),
                ("table", MIB_UDPROW_OWNER_PID * ANY_SIZE)]

class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte),
                ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwOwningPid", wintypes.DWORD)]

class MIB_UDP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwNumEntries", wintypes.DWORD),
                ("table", MIB_UDP6ROW_OWNER_PID * ANY_SIZE)]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [( "dwSize" , wintypes.DWORD) ,
                ( "cntUsage" , wintypes.DWORD),
                ( "th32ProcessID" , wintypes.DWORD),
                ( "th32DefaultHeapID" , ULONG_PTR),
                ( "th32ModuleID" , wintypes.DWORD) ,
                ( "cntThreads" , wintypes.DWORD) ,
                ( "th32ParentProcessID" , wintypes.DWORD) ,
                ( "pcPriClassBase" , wintypes.LONG) ,
                ( "dwFlags" , wintypes.DWORD),
                ( "szExeFile" , wintypes.CHAR * 260 )]

class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", wintypes.USHORT),
                ("sa_data", ctypes.c_char * 14)]

# typedef enum
# {
#     WINDIVERT_LAYER_NETWORK = 0,        /* Network layer. */
#     WINDIVERT_LAYER_NETWORK_FORWARD = 1,/* Network layer (forwarded packets) */
#     WINDIVERT_LAYER_FLOW = 2,           /* Flow layer. */
#     WINDIVERT_LAYER_SOCKET = 3,         /* Socket layer. */
#     WINDIVERT_LAYER_REFLECT = 4,        /* Reflect layer. */
# } WINDIVERT_LAYER, *PWINDIVERT_LAYER;
WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_LAYER_NETWORK_FORWARD = 1
WINDIVERT_LAYER_FLOW = 2
WINDIVERT_LAYER_SOCKET = 3
WINDIVERT_LAYER_REFLECT = 4

# #define WINDIVERT_FLAG_SNIFF            0x0001
# #define WINDIVERT_FLAG_DROP             0x0002
# #define WINDIVERT_FLAG_RECV_ONLY        0x0004
# #define WINDIVERT_FLAG_READ_ONLY        WINDIVERT_FLAG_RECV_ONLY
# #define WINDIVERT_FLAG_SEND_ONLY        0x0008
# #define WINDIVERT_FLAG_WRITE_ONLY       WINDIVERT_FLAG_SEND_ONLY
# #define WINDIVERT_FLAG_NO_INSTALL       0x0010
# #define WINDIVERT_FLAG_FRAGMENTS        0x0020
WINDIVERT_FLAG_SNIFF = 0x0001
WINDIVERT_FLAG_DROP = 0x0002
WINDIVERT_FLAG_RECV_ONLY = 0x0004
WINDIVERT_FLAG_READ_ONLY = WINDIVERT_FLAG_RECV_ONLY
WINDIVERT_FLAG_SEND_ONLY = 0x0008
WINDIVERT_FLAG_WRITE_ONLY = 0x0008
WINDIVERT_FLAG_NO_INSTALL = 0x0010
WINDIVERT_FLAG_FRAGMENTS = 0x0020

# typedef enum
# {
#     WINDIVERT_EVENT_NETWORK_PACKET = 0, /* Network packet. */
#     WINDIVERT_EVENT_FLOW_ESTABLISHED = 1,
#                                         /* Flow established. */
#     WINDIVERT_EVENT_FLOW_DELETED = 2,   /* Flow deleted. */
#     WINDIVERT_EVENT_SOCKET_BIND = 3,    /* Socket bind. */
#     WINDIVERT_EVENT_SOCKET_CONNECT = 4, /* Socket connect. */
#     WINDIVERT_EVENT_SOCKET_LISTEN = 5,  /* Socket listen. */
#     WINDIVERT_EVENT_SOCKET_ACCEPT = 6,  /* Socket accept. */
#     WINDIVERT_EVENT_SOCKET_CLOSE = 7,   /* Socket close. */
#     WINDIVERT_EVENT_REFLECT_OPEN = 8,   /* WinDivert handle opened. */
#     WINDIVERT_EVENT_REFLECT_CLOSE = 9,  /* WinDivert handle closed. */
# } WINDIVERT_EVENT, *PWINDIVERT_EVENT;
WINDIVERT_EVENT_NETWORK_PACKET = 0
WINDIVERT_EVENT_FLOW_ESTABLISHED = 1
WINDIVERT_EVENT_FLOW_DELETED = 2
WINDIVERT_EVENT_SOCKET_BIND = 3
WINDIVERT_EVENT_SOCKET_CONNECT = 4
WINDIVERT_EVENT_SOCKET_LISTEN = 5
WINDIVERT_EVENT_SOCKET_ACCEPT = 6
WINDIVERT_EVENT_SOCKET_CLOSE = 7
WINDIVERT_EVENT_REFLECT_OPEN = 8
WINDIVERT_EVENT_REFLECT_CLOSE = 9

WINDIVERT_LAYER = ctypes.c_uint
WINDIVERT_EVENT = ctypes.c_uint

windivertdll : ctypes.WinDLL = ctypes.WinDLL(r".\WinDivert\Lib\WinDivert.dll")
# windivertdll.WinDivertOpen.argtypes = [ ctypes.c_char_p, ctypes.c_uint, ctypes.c_int16, ctypes.c_uint64]
# windivertdll.WinDivertOpen.restype = wintypes.HANDLE

TH32CS_SNAPMODULE = 0x00000002
INVALID_HANDLE_VALUE = -1

class WINDIVERT_DATA_NETWORK(ctypes.Structure):
    _fields_ = [("IfIdx", ctypes.c_uint32),
                ("SubIfIdx", ctypes.c_uint32)]

class WINDIVERT_DATA_FLOW(ctypes.Structure):
    _fields_ = [('EndpointId', ctypes.c_uint64),
                ('ParentEndpointId', ctypes.c_uint64),
                ('ProcessId', ctypes.c_uint32),
                ('LocalAddr', ctypes.c_uint32 * 4),
                ('RemoteAddr', ctypes.c_uint32 * 4),
                ('LocalPort', ctypes.c_uint16),
                ('RemotePort', ctypes.c_uint16),
                ('Protocol', ctypes.c_uint8)]

class WINDIVERT_DATA_SOCKET(ctypes.Structure):
    _fields_ = [('EndpointId', ctypes.c_uint64),
                ('ParentEndpointId', ctypes.c_uint64),
                ('ProcessId', ctypes.c_uint32),
                ('LocalAddr', ctypes.c_uint32 * 4),
                ('RemoteAddr', ctypes.c_uint32 * 4),
                ('LocalPort', ctypes.c_uint16),
                ('RemotePort', ctypes.c_uint16),
                ('Protocol', ctypes.c_uint8)]

class WINDIVERT_DATA_REFLECT(ctypes.Structure):
    _fields_ = [('Timestamp', ctypes.c_int64),
                ('ProcessId', ctypes.c_uint32),
                ('Layer', WINDIVERT_LAYER),
                ('Flags', ctypes.c_uint64),
                ('Priority', ctypes.c_int16)]
                
class WINDIVERT_ADDRESS_DUMMYUNION(ctypes.Union):
    _fields_ = [("Network", WINDIVERT_DATA_NETWORK),
                ("Flow", WINDIVERT_DATA_FLOW),
                ("Socket", WINDIVERT_DATA_SOCKET),
                ("Reflect", WINDIVERT_DATA_REFLECT),
                ("Reserved3", ctypes.c_uint8 * 64)]

class WINDIVERT_ADDRESS(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("Timestamp", ctypes.c_int64),
                ("Layer", ctypes.c_uint32, 8),
                ("Event", ctypes.c_uint32, 8),
                ("Sniffed", ctypes.c_uint32, 1),
                ("Outbound", ctypes.c_uint32, 1),
                ("Loopback", ctypes.c_uint32, 1),
                ("Impostor", ctypes.c_uint32, 1),
                ("IPv6", ctypes.c_uint32, 1),
                ("IPChecksum", ctypes.c_uint32, 1),
                ("TCPChecksum", ctypes.c_uint32, 1),
                ("UDPChecksum", ctypes.c_uint32, 1),
                ("Reserved1", ctypes.c_uint32, 8),
                ("Reserved2", ctypes.c_uint32),
                ("u", WINDIVERT_ADDRESS_DUMMYUNION)]

#define PCAP_ERRBUF_SIZE 256
PCAP_ERRBUF_SIZE = 256

#define PCAP_SRC_IF_STRING "rpcap://"
PCAP_SRC_IF_STRING = ctypes.c_char_p(b"rpcap://")

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



#pid must be int or set
def find_local_tcp_ports_by_pid(pid) -> set[int]:
    tcptable_owner_pid = MIB_TCPTABLE_OWNER_PID()
    tcptable_owner_pid_size = wintypes.DWORD()
    error_code = wintypes.DWORD()
    local_tcp_port_list : set = set()

    error_code = ctypes.windll.iphlpapi.GetExtendedTcpTable(ctypes.byref(tcptable_owner_pid), ctypes.byref(tcptable_owner_pid_size), 3, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    if error_code == ERROR_INSUFFICIENT_BUFFER:
        ctypes.resize(tcptable_owner_pid, tcptable_owner_pid_size.value)
        ctypes.memset(ctypes.byref(tcptable_owner_pid), 0, tcptable_owner_pid_size.value)
        error_code = ctypes.windll.iphlpapi.GetExtendedTcpTable(ctypes.byref(tcptable_owner_pid), ctypes.byref(tcptable_owner_pid_size), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    
    if error_code != ERROR_SUCCESS:
        print("error : {}".format(error_code.value))
        exit()

    tcprow_owner_pid_arr = ctypes.cast(tcptable_owner_pid.table, ctypes.POINTER(MIB_TCPROW_OWNER_PID * tcptable_owner_pid.dwNumEntries))[0]

    if type(pid) == int:
        for tcprow_owner_pid in tcprow_owner_pid_arr:
            if tcprow_owner_pid.dwOwningPid == pid:
                local_tcp_port_list.add(tcprow_owner_pid.dwLocalPort)
    elif type(pid) == set:
        for tcprow_owner_pid in tcprow_owner_pid_arr:
            if tcprow_owner_pid.dwOwningPid in pid:
                local_tcp_port_list.add(tcprow_owner_pid.dwLocalPort)
    
    return local_tcp_port_list



#pid must be int or set
def find_local_tcp6_ports_by_pid(pid) -> set[int]:
    tcp6table_owner_pid = MIB_TCP6TABLE_OWNER_PID()
    tcp6table_owner_pid_size = wintypes.DWORD()
    error_code = wintypes.DWORD()
    local_tcp6_port_list : set = set()

    error_code = ctypes.windll.iphlpapi.GetExtendedTcpTable(ctypes.byref(tcp6table_owner_pid), ctypes.byref(tcp6table_owner_pid_size), 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)

    if error_code == ERROR_INSUFFICIENT_BUFFER:
        ctypes.resize(tcp6table_owner_pid, tcp6table_owner_pid_size.value)
        ctypes.memset(ctypes.byref(tcp6table_owner_pid), 0, tcp6table_owner_pid_size.value)
        error_code = ctypes.windll.iphlpapi.GetExtendedTcpTable(ctypes.byref(tcp6table_owner_pid), ctypes.byref(tcp6table_owner_pid_size), 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
    
    if error_code != ERROR_SUCCESS:
        print("error : {}".format(error_code.value))
        exit()

    tcp6row_owner_pid_arr = ctypes.cast(tcp6table_owner_pid.table, ctypes.POINTER(MIB_TCP6ROW_OWNER_PID * tcp6table_owner_pid.dwNumEntries))[0]
    
    if type(pid) == int:
        for tcp6row_owner_pid in tcp6row_owner_pid_arr:
            if tcp6row_owner_pid.dwOwningPid == pid:
                local_tcp6_port_list.add(tcp6row_owner_pid.dwLocalPort)
    elif type(pid) == set:
        for tcp6row_owner_pid in tcp6row_owner_pid_arr:
            if tcp6row_owner_pid.dwOwningPid in pid:
                local_tcp6_port_list.add(tcp6row_owner_pid.dwLocalPort)
    
    return local_tcp6_port_list



#pid must be int or set
def find_local_udp_ports_by_pid(pid) -> set[int]:
    udptable_owner_pid = MIB_UDPTABLE_OWNER_PID()
    udptable_owner_pid_size = wintypes.DWORD()
    error_code = wintypes.DWORD()
    local_udp_port_list : set = set()

    error_code = ctypes.windll.iphlpapi.GetExtendedUdpTable(ctypes.byref(udptable_owner_pid), ctypes.byref(udptable_owner_pid_size), 0, AF_INET, UDP_TABLE_OWNER_PID, 0)

    if error_code == ERROR_INSUFFICIENT_BUFFER:
        ctypes.resize(udptable_owner_pid, udptable_owner_pid_size.value)
        ctypes.memset(ctypes.byref(udptable_owner_pid), 0, udptable_owner_pid_size.value)
        error_code = ctypes.windll.iphlpapi.GetExtendedUdpTable(ctypes.byref(udptable_owner_pid), ctypes.byref(udptable_owner_pid_size), 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
    
    if error_code != ERROR_SUCCESS:
        print("error : {}".format(error_code))
        exit()

    udprow_owner_pid_arr = ctypes.cast(udptable_owner_pid.table, ctypes.POINTER(MIB_UDPROW_OWNER_PID * udptable_owner_pid.dwNumEntries))[0]

    if type(pid) == int:
        for udprow_owner_pid in udprow_owner_pid_arr:
            if udprow_owner_pid.dwOwningPid == pid:
                local_udp_port_list.add(udprow_owner_pid.dwLocalPort)
    elif type(pid) == set:
        for udprow_owner_pid in udprow_owner_pid_arr:
            if udprow_owner_pid.dwOwningPid in pid:
                local_udp_port_list.add(udprow_owner_pid.dwLocalPort)
    
    return local_udp_port_list



#pid be int or set
def find_local_udp6_ports_by_pid(pid : int) -> set[int]:
    udp6table_owner_pid = MIB_UDP6TABLE_OWNER_PID()
    udp6table_owner_pid_size = wintypes.DWORD()
    error_code = wintypes.DWORD()
    local_udp_port_list : set = set()

    error_code = ctypes.windll.iphlpapi.GetExtendedUdpTable(ctypes.byref(udp6table_owner_pid), ctypes.byref(udp6table_owner_pid_size), 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)

    if error_code == ERROR_INSUFFICIENT_BUFFER:
        ctypes.resize(udp6table_owner_pid, udp6table_owner_pid_size.value)
        ctypes.memset(ctypes.byref(udp6table_owner_pid), 0, udp6table_owner_pid_size.value)
        error_code = ctypes.windll.iphlpapi.GetExtendedUdpTable(ctypes.byref(udp6table_owner_pid), ctypes.byref(udp6table_owner_pid_size), 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)
    
    if error_code != ERROR_SUCCESS:
        print("error : {}".format(error_code))
        exit()

    udp6row_owner_pid_arr = ctypes.cast(udp6table_owner_pid.table, ctypes.POINTER(MIB_UDP6ROW_OWNER_PID * udp6table_owner_pid.dwNumEntries))[0]

    if type(pid) == int:
        for udp6row_owner_pid in udp6row_owner_pid_arr:
            if udp6row_owner_pid.dwOwningPid == pid:
                local_udp_port_list.add(udp6row_owner_pid.dwLocalPort)
    elif type(pid) == set:
        for udp6row_owner_pid in udp6row_owner_pid_arr:
            if udp6row_owner_pid.dwOwningPid in pid:
                local_udp_port_list.add(udp6row_owner_pid.dwLocalPort)
    
    return local_udp_port_list

def process_packet_caputre_by_pid(pid : int):
    print(type(windivertdll))

    # print(windivertdll.WINDIVERT_LAYER_SOCKET)

    # hSocketLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_RECV_ONLY)

    # HANDLE WinDivertOpen(
    # __in const char *filter,
    # __in WINDIVERT_LAYER layer,
    # __in INT16 priority,
    # __in UINT64 flags
    # );
    hFlowLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)

    if hFlowLayer == INVALID_HANDLE_VALUE:
        print("error_code : {}".format(win32api.GetLastError()))
        exit()

    addr = WINDIVERT_ADDRESS()
    # while True:
        # BOOL WinDivertRecv(
        # __in HANDLE handle,
        # __out_opt PVOID pPacket,
        # __in UINT packetLen,
        # __out_opt UINT *pRecvLen,
        # __out_opt WINDIVERT_ADDRESS *pAddr
        # );
    
    # while True:
    if windivertdll.WinDivertRecv(hFlowLayer, None, 0, None, ctypes.byref(addr)) == False:
        print(win32api.GetLastError())
        exit()

    # print("Timestamp = {0}".format(addr.Timestamp))
    # print("Event = {0}".format(addr.Event))
    # print("Sniffed = {0}".format(addr.Sniffed))
    # print("Outbound = {0}".format(addr.Outbound))
    # print("Loopback = {0}".format(addr.Loopback))
    # print("Impostor = {0}".format(addr.Impostor))
    # print("IPv6 = {0}".format(addr.IPv6))
    # print("IPChecksum = {0}".format(addr.IPChecksum))
    # print("TCPChecksum = {0}".format(addr.TCPChecksum))
    # print("UDPChecksum = {0}".format(addr.UDPChecksum))

    local_addr = (wintypes.CHAR * 40)()
    remote_addr = (wintypes.CHAR * 40)()
    windivertdll.WinDivertHelperFormatIPv4Address(addr.Flow.LocalAddr[0], local_addr, 40)
    windivertdll.WinDivertHelperFormatIPv4Address(addr.Flow.RemoteAddr[0], remote_addr, 40)

    # print("EndpointId = {0}".format(addr.Flow.EndpointId))
    # print("ParentEndpointId = {0}".format(addr.Flow.ParentEndpointId))
    print("ProcessId = {0}".format(addr.Flow.ProcessId))
    print("LocalAddr = {0}".format(local_addr.value.decode("UTF-8")))
    print("RemoteAddr = {0}".format(remote_addr.value.decode("UTF-8")))
    print("LocalPort = {0}".format(addr.Flow.LocalPort))
    print("RemotePort = {0}".format(addr.Flow.RemotePort))
    print("Protocol = {0}".format(addr.Flow.Protocol))

    print(ctypes.sizeof(addr))

    if windivertdll.WinDivertClose(hFlowLayer) == False:
        print(win32api.GetLastError())

# 극단적으로 짧게 생성되어 죽는 프로세스에 대해서는 캡처를 할 수 없는 문제가 있음
# 이유 : pid로 프로세스프로세스 핸들을 통해 프로세스 이름을 얻는데, 이 과정중에 프로세스가 죽으면 프로세스 이름을 얻을 수 없게됨
# 가끔식 set remove 과정중 오류가 발생. 원인 조사중
def process_packet_caputre_by_process_name(process_name : str):
    tcp_local_port_set : set = set()
    tcp6_local_port_set : set = set()
    udp_local_port_set : set = set()
    udp6_local_port_set : set = set()
    windivert_addr = WINDIVERT_ADDRESS()
    process_path_by_pid_buffer = (wintypes.CHAR * win32con.MAX_PATH)()
    process_path_by_pid_size = 0
    process_name_by_pid : str = str()
    process_path_to_name_regex = re.compile(r'\\([^\\]*)$')

    hFlowLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)

    if hFlowLayer == INVALID_HANDLE_VALUE:
        print("error_code : {}".format(win32api.GetLastError()))
        exit()

    init_pid_set : set = set()
    hProcessSnapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, None)
    process_entry_32 = PROCESSENTRY32()
    process_entry_32.dwSize = ctypes.sizeof(process_entry_32)

    if hProcessSnapshot == INVALID_HANDLE_VALUE:
        print("error_code : {}".format(win32api.GetLastError()))
        exit()

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.byref(process_entry_32))
    flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32)) # need to pass pid 0

    while flag:
        if process_entry_32.szExeFile.decode("UTF-8") == process_name:
            init_pid_set.add(process_entry_32.th32ProcessID)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32))
    
    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)
        
    tcp_local_port_set = find_local_tcp_ports_by_pid(init_pid_set)
    tcp6_local_port_set = find_local_tcp6_ports_by_pid(init_pid_set)
    udp_local_port_set = find_local_udp_ports_by_pid(init_pid_set)
    udp6_local_port_set = find_local_udp6_ports_by_pid(init_pid_set)

    while True:
        if windivertdll.WinDivertRecv(hFlowLayer, None, 0, None, ctypes.byref(windivert_addr)) == False:
            print("error_code : {}".format(win32api.GetLastError()))
            raise Exception("1")
            exit()

        hProc : wintypes.HANDLE = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, win32con.FALSE, windivert_addr.Flow.ProcessId)

        if hProc == INVALID_HANDLE_VALUE:
            print("error_code : {}".format(win32api.GetLastError()))
            raise Exception("2")
            exit()
        
        process_path_size = wintypes.DWORD(win32con.MAX_PATH)
        if ctypes.windll.kernel32.QueryFullProcessImageNameA(hProc, 0, ctypes.byref(process_path_by_pid_buffer), ctypes.byref(process_path_size)) == False:
            # print("error_code : {}".format(win32api.GetLastError()))
            # raise Exception("3")
            process_name_by_pid = None

        ctypes.windll.kernel32.CloseHandle(hProc)

        regex_result = process_path_to_name_regex.search(process_path_by_pid_buffer.value.decode("UTF-8"))
        if regex_result != None:
            process_name_by_pid = regex_result.group(1)

        print(process_name_by_pid)

        try:
            if process_name_by_pid == process_name:
                print("pass")
                if windivert_addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED:
                    if windivert_addr.IPv6 == 0:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            tcp_local_port_set.add(windivert_addr.Flow.LocalPort)
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            udp_local_port_set.add(windivert_addr.Flow.LocalPort)
                    else:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            tcp6_local_port_set.add(windivert_addr.Flow.LocalPort)
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            udp6_local_port_set.add(windivert_addr.Flow.LocalPort)
                elif windivert_addr.Event == WINDIVERT_EVENT_FLOW_DELETED:
                    if windivert_addr.IPv6 == 0:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            tcp_local_port_set.remove(windivert_addr.Flow.LocalPort)

                        # windivert는 udp는 암시적 흐름을 형성한다. 이러한 암시적 흐름은
                        # 1) 일정시간이 지나거나 2) 해당 포트를 다른 프로세스가 사용하면 DELETE 된다.
                        # 따라서 기존 udp 포트에서 없던 포트에 remove 하라는 경우가 생길 수 있다.
                        # 그러므로 이 부분을 예외 처리해준다.
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP and windivert_addr.Flow.LocalPort in udp_local_port_set:
                            udp_local_port_set.remove(windivert_addr.Flow.LocalPort)
                    else:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            tcp6_local_port_set.remove(windivert_addr.Flow.LocalPort)
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP and windivert_addr.Flow.LocalPort in udp6_local_port_set:
                            udp6_local_port_set.remove(windivert_addr.Flow.LocalPort)
        except Exception as e:
            print("error : ", e)
            raise Exception("error")
    
    
    if windivertdll.WinDivertClose(hFlowLayer) == False:
        print("error_code : {}".format(win32api.GetLastError()))


# process_packet_caputre_by_pid()

tcp_port_list = find_local_tcp_ports_by_pid({24892, 4})
tcp6_port_list = find_local_tcp6_ports_by_pid(24892)
udp_port_list = find_local_udp_ports_by_pid(24892)
udp6_port_list = find_local_udp6_ports_by_pid(24892)

for port in tcp_port_list:
    print(port)
print("---------udp----------")
for port in udp_port_list:
    print(port)
# for port in udp6_port_list:
#     print(port)

process_packet_caputre_by_process_name("chrome.exe")