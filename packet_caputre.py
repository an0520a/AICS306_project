import ctypes
from ctypes import wintypes
from ctypes import windll
import win32con
import win32api

WINDIVERT_LAYER = ctypes.c_uint
(WINDIVERT_LAYER_NETWORK, WINDIVERT_LAYER_NETWORK_FORWARD, WINDIVERT_LAYER_FLOW, WINDIVERT_LAYER_SOCKET, WINDIVERT_LAYER_REFLECT) = (0, 1, 2, 3, 4)
(WINDIVERT_FLAG_SNIFF, WINDIVERT_FLAG_DROP, WINDIVERT_FLAG_RECV_ONLY, WINDIVERT_FLAG_READ_ONLY, WINDIVERT_FLAG_SEND_ONLY, WINDIVERT_FLAG_WRITE_ONLY, WINDIVERT_FLAG_NO_INSTALL, WINDIVERT_FLAG_FRAGMENTS) = \
( 0x0001, 0x0002, 0x0004, 0x0004, 0x0008, 0x0008, 0x0010, 0x0020)

INVALID_HANDLE_VALUE = -1

#define WINDIVERT_FLAG_SNIFF            0x0001
#define WINDIVERT_FLAG_DROP             0x0002
#define WINDIVERT_FLAG_RECV_ONLY        0x0004
#define WINDIVERT_FLAG_READ_ONLY        WINDIVERT_FLAG_RECV_ONLY
#define WINDIVERT_FLAG_SEND_ONLY        0x0008
#define WINDIVERT_FLAG_WRITE_ONLY       WINDIVERT_FLAG_SEND_ONLY
#define WINDIVERT_FLAG_NO_INSTALL       0x0010
#define WINDIVERT_FLAG_FRAGMENTS        0x0020

windivertdll : ctypes.WinDLL = ctypes.WinDLL("./WinDivert/WinDivert.dll")
# windivertdll.WinDivertOpen.argtypes = [ ctypes.c_char_p, ctypes.c_uint, ctypes.c_int16, ctypes.c_uint64]
# windivertdll.WinDivertOpen.restype = wintypes.HANDLE

MAX_PACKET_SIZE : int = 32768


class WINDIVERT_DATA_NETWORK(ctypes.Structure):
    _fields_ = [("IfIdx", ctypes.c_uint32),
                ("SubIfIdx", ctypes.c_uint32)]

class WINDIVERT_DATA_FLOW(ctypes.Structure):
    _fields_ = [('Endpoint', ctypes.c_uint64),
                ('ParentEndpoint', ctypes.c_uint64),
                ('ProcessId', ctypes.c_uint32),
                ('LocalAddr', ctypes.c_uint32 * 4),
                ('RemoteAddr', ctypes.c_uint32 * 4),
                ('LocalPort', ctypes.c_uint16),
                ('RemotePort', ctypes.c_uint16),
                ('Protocol', ctypes.c_uint8)]

class WINDIVERT_DATA_SOCKET(ctypes.Structure):
    _fields_ = [('Endpoint', ctypes.c_uint64),
                ('ParentEndpoint', ctypes.c_uint64),
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
                
class WINDIVERT_ADDRESS_DUMMYUNION(ctypes.Structure):
    _fields_ = [("Network", WINDIVERT_DATA_NETWORK),
                ("Flow", WINDIVERT_DATA_FLOW),
                ("Socket", WINDIVERT_DATA_SOCKET),
                ("Reflect", WINDIVERT_DATA_REFLECT)]

class WINDIVERT_ADDRESS(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", WINDIVERT_ADDRESS_DUMMYUNION),
                ("Timestamp", ctypes.c_int64),
                ("Layer", ctypes.c_uint64, 8),
                ("Event", ctypes.c_uint64, 8),
                ("Sniffed", ctypes.c_uint64, 1),
                ("Outbound", ctypes.c_uint64, 1),
                ("Loopback", ctypes.c_uint64, 1),
                ("Impostor", ctypes.c_uint64, 1),
                ("IPv6", ctypes.c_uint64, 1),
                ("IPChecksum", ctypes.c_uint64, 1),
                ("TCPChecksum", ctypes.c_uint64, 1),
                ("UDPChecksum", ctypes.c_uint64, 1),
                ("u", WINDIVERT_ADDRESS_DUMMYUNION)]

def process_packet_caputre_by_pid(pid : int):
    print(type(windivertdll))

    # print(windivertdll.WINDIVERT_LAYER_SOCKET)
    
    hSocketLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_RECV_ONLY)

    if hSocketLayer == INVALID_HANDLE_VALUE:
        print(win32api.GetLastError())

    event = (wintypes.BYTE * MAX_PACKET_SIZE)()
    recv_len = wintypes.UINT()


    windivertdll.WinDivertRecv(hSocketLayer, )
    
    if windivertdll.WinDivertClose(hSocketLayer) == False:
        print(win32api.GetLastError())

process_packet_caputre_by_pid(0)