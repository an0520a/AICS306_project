import ctypes
from ctypes import wintypes

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

TH32CS_SNAPMODULE = 0x00000002
INVALID_HANDLE_VALUE = -1
CP_ACP = 0

#DWORD_PTR과 UNLONG_PTR은 32비트인지, 64비트인지의 여부에 따라 크기가 다름. 
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong): #64bit
    DWORD_PTR = ctypes.c_ulonglong
    ULONG_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong): #32bit
    DWORD_PTR = ctypes.c_ulong
    ULONG_PTR = ctypes.c_ulong

__time32_t = ctypes.c_long
__time64_t = ctypes.c_longlong

if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong): #64bit
    time_t = __time64_t
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong): #32bit
    time_t = __time32_t

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize" , wintypes.DWORD),
                ("cntUsage" , wintypes.DWORD),
                ("th32ProcessID" , wintypes.DWORD),
                ("th32DefaultHeapID" , ULONG_PTR),
                ("th32ModuleID" , wintypes.DWORD),
                ("cntThreads" , wintypes.DWORD),
                ("th32ParentProcessID" , wintypes.DWORD),
                ("pcPriClassBase" , wintypes.LONG),
                ("dwFlags" , wintypes.DWORD),
                ("szExeFile" , wintypes.CHAR * 260)]

class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [ ( "cb" , wintypes.DWORD) ,
                 ( "CommitTotal" , ctypes.c_size_t ),
                 ( "CommitLimit" , ctypes.c_size_t ),
                 ( "CommitPeak" , ctypes.c_size_t ),
                 ( "PhysicalTotal" , ctypes.c_size_t ) ,
                 ( "PhysicalAvailable" , ctypes.c_size_t ) ,
                 ( "SystemCache" , ctypes.c_size_t ) ,
                 ( "KernelTotal" , ctypes.c_size_t ) ,
                 ( "KernelPaged" , ctypes.c_size_t ),
                 ( "KernelNonpaged" , ctypes.c_size_t ),
                 ( "PageSize" , ctypes.c_size_t ),
                 ( "HandleCount" , wintypes.DWORD ),
                 ( "ProcessCount" , wintypes.DWORD ),
                 ( "ThreadCount" , wintypes.DWORD ) ]

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [ ( "dwLength" , wintypes.DWORD) ,
                 ( "dwMemoryLoad" , wintypes.DWORD ),
                 ( "ullTotalPhys" , ctypes.c_uint64 ),
                 ( "ullAvailPhys" , ctypes.c_uint64 ),
                 ( "ullTotalPageFile" , ctypes.c_uint64 ) ,
                 ( "ullAvailPageFile" , ctypes.c_uint64 ) ,
                 ( "ullTotalVirtual" , ctypes.c_uint64 ) ,
                 ( "ullAvailVirtual" , ctypes.c_uint64 ) ,
                 ( "ullAvailExtendedVirtual" , ctypes.c_uint64 ) ]

class SYSTEM_INFO_DUMMYSTRUCT(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", ctypes.c_ushort),
                ("wReserved", ctypes.c_short)]

class SYSTEM_INFO_DUMMYUNION(ctypes.Union):
    _anonymous_ = ("s",)
    _fields_ = [('dwOemId', ctypes.c_ulong),
                ('s', SYSTEM_INFO_DUMMYSTRUCT)]

class SYSTEM_INFO(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", SYSTEM_INFO_DUMMYUNION),
                ("dwPageSize", ctypes.c_ulong),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", DWORD_PTR),
                ("dwNumberOfProcessors", ctypes.c_ulong),
                ("dwProcessorType", ctypes.c_ulong),
                ("dwAllocationGranularity", ctypes.c_ulong),
                ("wProcessorLevel", ctypes.c_ushort),
                ("wProcessorRevision", ctypes.c_ushort)]

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

class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", wintypes.USHORT),
                ("sa_data", ctypes.c_char * 14)]

class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long),
                ("tv_usec", ctypes.c_long)]

class tm(ctypes.Structure):
    _fields_ = [("tm_sec", ctypes.c_int),
                ("tm_min", ctypes.c_int),
                ("tm_hour", ctypes.c_int),
                ("tm_mday", ctypes.c_int),
                ("tm_mon", ctypes.c_int),
                ("tm_year", ctypes.c_int),
                ("tm_wday", ctypes.c_int),
                ("tm_yday", ctypes.c_int),
                ("tm_isdst", ctypes.c_int)]