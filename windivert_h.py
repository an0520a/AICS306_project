import ctypes
from ctypes import wintypes

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