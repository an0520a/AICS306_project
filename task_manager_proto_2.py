from concurrent.futures import process
from re import I
import sys
import win32api
import win32process
import win32con
import win32security
import win32process
import win32gui
import winnt
import pywintypes
import ctypes
from ctypes import wintypes
from ctypes import windll
import elevate
import os
import time
import datetime
from dataclasses import dataclass
from dataclasses import field

@dataclass(order = True)
class ProcessInfo:
    process_pid : int = None
    process_name : str = ""
    process_path : str = ""
    process_owner : str = ""
    process_owner_domain : str = ""
    process_owner_type : int = None
    process_path : str = ""
    process_time_info_dict : dict = field(default_factory=dict)
    process_memory_info_dict : dict = field(default_factory=dict)
    measurement_time : wintypes.LARGE_INTEGER = wintypes.LARGE_INTEGER()
    token_flag : bool = False

@dataclass(order = True)
class PreprocessedProcessInfo(ProcessInfo):
    process_memory_usage : float = 0 # 단위 : KB
    process_cpu_usage_rate: float = 0
    process_memory_usage_rate : float = 0

@dataclass
class HardSystemMemoryInfo: # 변동되지 않는 메모리 정보
    kInstall : int = None
    kHardwareReserved : int = None
    kTotal : int = None

@dataclass
class SoftSystemMemoryInfo: # 변동되는 메모리 정보
    available : int = None

@dataclass
class SystemMemoryInfo:
    hard_system_memory_info : HardSystemMemoryInfo = field(default_factory=dataclass)
    soft_system_memory_info : SoftSystemMemoryInfo = field(default_factory=dataclass)

#DWORD_PTR과 UNLONG_PTR은 32비트인지, 64비트인지의 여부에 따라 크기가 다름. 
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
    ULONG_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong
    ULONG_PTR = ctypes.c_ulong

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [ ( "dwSize" , wintypes.DWORD) ,
                 ( "cntUsage" , wintypes.DWORD ),
                 ( "th32ProcessID" , wintypes.DWORD ),
                 ( "th32DefaultHeapID" , ULONG_PTR ),
                 ( "th32ModuleID" , wintypes.DWORD ) ,
                 ( "cntThreads" , wintypes.DWORD ) ,
                 ( "th32ParentProcessID" , wintypes.DWORD ) ,
                 ( "pcPriClassBase" , wintypes.LONG ) ,
                 ( "dwFlags" , wintypes.DWORD ),
                 ( "szExeFile" , wintypes.CHAR * 260 ) ]

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

TH32CS_SNAPMODULE = 0x00000002
INVALID_HANDLE_VALUE = -1
CP_ACP = 0
FREQUENCY = wintypes.LARGE_INTEGER()
NUMBER_OF_PROCESS = 0

def kill_process(process_pid):
    hProc = win32api.OpenProcess(
                win32con.PROCESS_TERMINATE, win32con.FALSE,
                process_pid
            )
    win32api.TerminateProcess(hProc, 1)
    win32api.CloseHandle(hProc)

def EnumWindowProc(hWnd, lParam):		
    if win32gui.GetParent(hWnd) == None:		
        pid = 0;		
        pid = win32process.GetWindowThreadProcessId(hWnd)		
        if pid == lParam:			
            win32gui.PostMessage(hWnd, win32con.WM_CLOSE, 0, 0)
        return False
    return True

def is_admin():
    try:
        return windll.shell32.IsUserAnAdmin()
    except:
        return False

# input value : https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
# 실패하면 False를 반환
def set_privilege(szPrivilege : str):
    hToken = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
    )
    # win32security.OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess)
        # Do it
            # 프로세스의 토큰 핸들을 획득한다.
        # Param
            # ProcessHandle : 프로세스 핸들
            # DesiredAccess : 토큰 접근 권한
        # return
            # 프로세스의 토큰을 반환 (Handle)

    if hToken == 0:
        return False


    luid = win32security.LookupPrivilegeValue(None, szPrivilege)
    # LUID LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName)
        # Do it
            # 명시된 권한을 표현할 LUID를 반환한다. LUID는 특정 권한을 표현해주는 구조체이다.
        # Param
            # lpSystemName : 명시된 특권을 찾기 위한 특정 시스템 이름. NULL을 넘기면 알아서 시스템에서 찾으려 시도
            # lpName : 특권 이름
            # 종류는 다음을 참조
                # https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
            # return
                # 프로세스의 토큰을 반환 (Handle)

    if luid == 0:
        return False


    new_token_privilege = [(luid, win32con.SE_PRIVILEGE_ENABLED)]
    '''
    new_token_privilege는 TOKEN_PRIVILEGES로, 파이썬에선 아마 다음 구조체의 리스트? :
    typedef struct _TOKEN_PRIVILEGES {
        LUID               luid;
        PRIVILEGE          Privilege;
    } TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;
    
        luid : 권한이 명시된 구초체
        Privilege : 특권 속성 값
            - SE_PRIVILEGE_ENABLED : 권한이 활성화 됩니다.
            - SE_PRIVILEGE_ENABLED_BY_DEFAULT : 권한은 기본적으로 사용됩니다.
            - SE_PRIVILEGE_REMOVED : 권한을 제거하는데 사용
            - SE_PRIVILEGE_USED_FOR_ACCESS : 객체 또는 서비스에 엑세스하는데 사용
    '''

    win32security.AdjustTokenPrivileges(hToken, win32con.FALSE, new_token_privilege)
    # AdjustTokenPrivileges(HANDLE TockenHandle, BOOL DisableAllPrivileges, TOKEN_PRIVILEGES NewState)
        # Do it
            # 토큰의 권한을 설정
        # Param
            # TockenHandle : 권한을 설정할 토큰 핸들
            # DisableAllPrivileges : 토큰의 모든 권한을 비활성화 할지 정함.
            #                        TRUE라면 모든 권한을 비활성화. FALSE라면 권한을 수정
            # NewState : 새로 설정활 권한

    if win32api.GetLastError():
        return False

    win32api.CloseHandle(hToken)

    return True

# 현재 프로세스의 리스트와 정보를 ProcessInfo dataclass의 리스트로 반환 
def get_process_info_list() -> list[ProcessInfo] :
    process_info_list = []
    hProcessSnapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, None)
    process_entry_32 = PROCESSENTRY32()
    process_entry_32.dwSize = ctypes.sizeof(process_entry_32)

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.pointer(process_entry_32))

    while flag:
        process_info = ProcessInfo()
        process_info.process_name = process_entry_32.szExeFile.decode("UTF-8")
        process_info.process_pid = process_entry_32.th32ProcessID
        
        try:
            hProc = win32api.OpenProcess(
                win32con.PROCESS_QUERY_LIMITED_INFORMATION, win32con.FALSE,
                process_info.process_pid
            )

            hToken = win32security.OpenProcessToken(
                hProc,
                win32con.TOKEN_QUERY
            )

            token_user = win32security.GetTokenInformation(hToken, win32security.TokenOwner)
            process_info.process_owner, process_info.process_owner_domain, process_info.process_owner_type = \
                win32security.LookupAccountSid(
                None, token_user
            )

            exe_name_size = wintypes.DWORD(win32con.MAX_PATH)
            exe_name = (wintypes.CHAR * exe_name_size.value)()
            ctypes.windll.kernel32.QueryFullProcessImageNameA(hProc.__int__(), 0, ctypes.byref(exe_name), ctypes.byref(exe_name_size))

            process_info.process_path = str(exe_name.value.decode("UTF-8"))

            process_info.process_time_info_dict = win32process.GetProcessTimes(hProc)
            process_info.process_memory_info_dict = win32process.GetProcessMemoryInfo(hProc)

            measurement_time = wintypes.LARGE_INTEGER()
            ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(measurement_time))
            process_info.measurement_time = measurement_time
            process_info.token_flag = True

            win32api.CloseHandle(hToken)
            win32api.CloseHandle(hProc)
            
        except Exception as e:\
            process_info.process_owner = "Unknown"

        process_info_list.append(process_info)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.pointer(process_entry_32))

    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)

    return process_info_list

def get_hard_system_memory_info() -> HardSystemMemoryInfo:
    hard_system_memory_info = HardSystemMemoryInfo()

    total_memory_in_kilobytes = ctypes.c_ulonglong()
    ctypes.windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(total_memory_in_kilobytes))
    hard_system_memory_info.kInstall = total_memory_in_kilobytes.value * 1024

    performance_information = PERFORMANCE_INFORMATION()
    performance_information.cb = ctypes.sizeof(performance_information)
    ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(performance_information), ctypes.sizeof(performance_information))
    hard_system_memory_info.kTotal = performance_information.PhysicalTotal * performance_information.PageSize
    hard_system_memory_info.kHardwareReserved = hard_system_memory_info.kInstall - hard_system_memory_info.kTotal

    return hard_system_memory_info

def get_soft_system_memory_info() -> SoftSystemMemoryInfo:
    soft_system_memory_info = SoftSystemMemoryInfo()

    memory_status_ex = MEMORYSTATUSEX()
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status_ex))
    soft_system_memory_info.available = memory_status_ex.ullAvailPhys

    return soft_system_memory_info

def get_system_memory_info() -> SystemMemoryInfo:
    system_memory_info = SystemMemoryInfo()
    system_memory_info.hard_system_memory_info = get_hard_system_memory_info()
    system_memory_info.soft_system_memory_info = get_soft_system_memory_info()
    
    return system_memory_info

def preprocessing_process_info(prev_process_info_list : list[ProcessInfo], process_info_list : list[ProcessInfo]) -> list[PreprocessedProcessInfo]:
    preprocessed_process_info_list = []

    process_info_list.sort()
    prev_process_info_list.sort()

    i = 0
    j = 0

    kTotalMemorySize = get_hard_system_memory_info().kTotal

    process_info_list_len = len(process_info_list)
    prev_process_info_list_len = len(prev_process_info_list)

    def process_info_list_to_pre_processed_process_info(_preprocessed_process_info : PreprocessedProcessInfo, _process_info :ProcessInfo):
        _preprocessed_process_info.process_name = _process_info.process_name
        _preprocessed_process_info.process_pid = _process_info.process_pid
        _preprocessed_process_info.process_path = _process_info.process_path
        _preprocessed_process_info.measurement_time = _process_info.measurement_time
        _preprocessed_process_info.process_memory_info_dict = _process_info.process_memory_info_dict
        _preprocessed_process_info.process_time_info_dict = _process_info.process_time_info_dict
        _preprocessed_process_info.process_owner = _process_info.process_owner
        _preprocessed_process_info.process_owner_domain = _process_info.process_owner_domain
        _preprocessed_process_info.process_owner_type = _process_info.process_owner_type

    while i < process_info_list_len and j < prev_process_info_list_len:
        preprocessed_process_info = PreprocessedProcessInfo()

        if process_info_list[i].token_flag and prev_process_info_list[j].token_flag :
            if process_info_list[i].process_pid == prev_process_info_list[j].process_pid :
                if process_info_list[i].process_time_info_dict["CreationTime"] == prev_process_info_list[j].process_time_info_dict["CreationTime"]:
                    process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                    preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / 1024.0
                    preprocessed_process_info.process_memory_usage_rate = (100 * preprocessed_process_info.process_memory_info_dict["WorkingSetSize"]) / kTotalMemorySize
                    
                    process_time = process_info_list[i].process_time_info_dict["KernelTime"] + process_info_list[i].process_time_info_dict["UserTime"]
                    prev_process_time = prev_process_info_list[j].process_time_info_dict["KernelTime"] + prev_process_info_list[j].process_time_info_dict["UserTime"]
                    elapsed_100nanoseconds = process_info_list[i].measurement_time.value - prev_process_info_list[j].measurement_time.value
                    elapsed_100nanoseconds *= 100000 # change unit.
                    elapsed_100nanoseconds /= FREQUENCY.value
                    preprocessed_process_info.process_cpu_usage_rate = (process_time - prev_process_time) / (elapsed_100nanoseconds * NUMBER_OF_PROCESS)
                    preprocessed_process_info_list.append(preprocessed_process_info)

                else: # 새로운 프로세스가 생긴 케이스 (기존 프로세스와 pid가 같음)
                    process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                    preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / 1024.0
                    preprocessed_process_info.process_memory_usage_rate = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / kTotalMemorySize

                    preprocessed_process_info.process_cpu_usage_rate = 0

                    preprocessed_process_info_list.append(preprocessed_process_info)

            else:
                if process_info_list[i].process_pid < prev_process_info_list[j].process_pid:  # 새로운 프로세스가 생긴 케이스 (기존 프로세스와 pid가 다름)
                    while process_info_list[i].process_pid < prev_process_info_list[j].process_pid:
                        process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                        preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / 1024.0
                        preprocessed_process_info.process_memory_usage_rate = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / kTotalMemorySize

                        preprocessed_process_info.process_cpu_usage_rate = 0

                        preprocessed_process_info_list.append(preprocessed_process_info)

                        i += 1

                    continue

                if process_info_list[i].process_pid > prev_process_info_list[j].process_pid:
                    while process_info_list[i].process_pid > prev_process_info_list[j].process_pid: # 있던 프로세스가 죽은 케이스
                        j += 1

                    continue
                
        else:
            if process_info_list[i].process_pid == prev_process_info_list[i].process_pid:
                preprocessed_process_info.process_name = process_info_list[i].process_name
                preprocessed_process_info.process_pid = process_info_list[i].process_pid
                preprocessed_process_info.measurement_time = process_info_list[i].measurement_time

                preprocessed_process_info_list.append(preprocessed_process_info)

            else:
                if process_info_list[i].process_pid < prev_process_info_list[j].process_pid:  # 새로운 프로세스가 생긴 케이스
                    while process_info_list[i].process_pid < prev_process_info_list[j].process_pid:
                        preprocessed_process_info.process_name = process_info_list[i].process_name
                        preprocessed_process_info.process_pid = process_info_list[i].process_pid
                        preprocessed_process_info.measurement_time = process_info_list[i].measurement_time

                        preprocessed_process_info_list.append(preprocessed_process_info)

                        i += 1

                    continue

                if process_info_list[i].process_pid > prev_process_info_list[j].process_pid:
                    while process_info_list[i].process_pid > prev_process_info_list[j].process_pid: # 있던 프로세스가 죽은 케이스
                        j += 1

                    continue

        i += 1
        j += 1

    for k in range(i, process_info_list_len):
        preprocessed_process_info = PreprocessedProcessInfo()

        if process_info_list[k].token_flag:
            preprocessed_process_info.process_name = process_info_list[k].process_name
            preprocessed_process_info.process_pid = process_info_list[k].process_pid
            preprocessed_process_info.process_memory_info_dict = process_info_list[k].process_memory_info_dict
            preprocessed_process_info.process_time_info_dict = process_info_list[k].process_time_info_dict
            preprocessed_process_info.process_owner = process_info_list[k].process_owner
            preprocessed_process_info.process_owner_domain = process_info_list[k].process_owner_domain
            preprocessed_process_info.process_owner_type = process_info_list[k].process_owner_type

            preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / 1024.0
            preprocessed_process_info.process_memory_usage_rate = preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / kTotalMemorySize

            preprocessed_process_info.process_cpu_usage_rate = 0
        else:
            preprocessed_process_info.process_name = process_info_list[k].process_name
            preprocessed_process_info.process_pid = process_info_list[k].process_pid

        preprocessed_process_info_list.append(preprocessed_process_info)

    return preprocessed_process_info_list

def global_init() -> None:
    global NUMBER_OF_PROCESS
    global FREQUENCY
    
    system_info = SYSTEM_INFO()
    ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(system_info))
    NUMBER_OF_PROCESS = system_info.dwNumberOfProcessors
    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(FREQUENCY))

def main():
    elevate.elevate(show_console = True)
    if set_privilege(win32con.SE_DEBUG_NAME) == False:
        print("error : can not set privilege")
    
    global_init()

    process_manager_update_time = 1

    prev_process_info_list = get_process_info_list()
    time.sleep(process_manager_update_time)

    while True:

        process_info_list = get_process_info_list()

        preprocessed_process_info_list = preprocessing_process_info(prev_process_info_list, process_info_list)

        print("%-25.25s\t%-5s\t%-15.15s\t%-14.14s\t%-12.12s\t%-17.17s" % (
            "name", 
            "pid", 
            "owner", 
            "cpu_usage_rate", 
            "memory_usage",
            "memory_usage_rate")
        )

        for process_info in preprocessed_process_info_list:
            print("%-25.25s\t%-5d\t%-15.15s\t%-14.2f\t%-12.12s\t%-17.2f" % (
                process_info.process_name, 
                process_info.process_pid, 
                process_info.process_owner, 
                process_info.process_cpu_usage_rate, 
                (str(process_info.process_memory_usage) + " " + "K"),
                process_info.process_memory_usage_rate)
            )


        prev_process_info_list = process_info_list
        time.sleep(process_manager_update_time)
        break

    os.system("pause")

if __name__ == '__main__':
    main()