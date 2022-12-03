import ctypes
from ctypes import wintypes
from ctypes import windll
import win32con
import win32api

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

windivertdll : ctypes.WinDLL = ctypes.WinDLL("./WinDivert/WinDivert.dll")
# windivertdll.WinDivertOpen.argtypes = [ ctypes.c_char_p, ctypes.c_uint, ctypes.c_int16, ctypes.c_uint64]
# windivertdll.WinDivertOpen.restype = wintypes.HANDLE

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

#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
ERROR_SUCCESS = 0
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122

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

def find_local_tcp_ports_by_pid(pid : int) -> list[int]:
    tcptable_owner_pid = MIB_TCPTABLE_OWNER_PID()
    tcptable_owner_pid_size = wintypes.DWORD()
    error_code = wintypes.DWORD()
    local_tcp_port_list = []

    ctypes.windll.kernel32.GetExtendedTcpTable(ctypes.byref(tcptable_owner_pid), ctypes.byref(tcptable_owner_pid_size), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    if error_code == ERROR_INSUFFICIENT_BUFFER:
        ctypes.resize(tcptable_owner_pid, tcptable_owner_pid_size.value)
        ctypes.memset(ctypes.byref(tcptable_owner_pid), 0, tcptable_owner_pid_size.value)
        error_code = ctypes.windll.kernel32.GetExtendedTcpTable(ctypes.byref(tcptable_owner_pid), ctypes.byref(tcptable_owner_pid_size), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    
    if error_code != ERROR_SUCCESS:
        print("error : {}".format(error_code))
        exit()
    
    for i in range(0, tcptable_owner_pid.dwNumEntries):
        if tcptable_owner_pid.table[i].dwOwningPid == pid:
            local_tcp_port_list.append(tcptable_owner_pid.table[i].dwLocalPort)
    
    return local_tcp_port_list

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
    hSocketLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)

    if hSocketLayer == INVALID_HANDLE_VALUE:
        print(win32api.GetLastError())
    


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
    if windivertdll.WinDivertRecv(hSocketLayer, None, 0, None, ctypes.pointer(addr)) == False:
        print(win32api.GetLastError())

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

    if windivertdll.WinDivertClose(hSocketLayer) == False:
        print(win32api.GetLastError())



process_packet_caputre_by_pid(0)