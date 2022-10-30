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
from ctypes import GetLastError, wintypes
from ctypes import windll
import elevate
import os
import time
import schedule
import datetime
from dataclasses import dataclass
from dataclasses import field

@dataclass(order = True)
class ProcessInfo:
    process_pid : int = None
    process_name : str = None
    process_owner : str = None
    process_owner_domain : str = None
    process_owner_type : int = None
    process_time_info_dict : dict = field(default_factory=dict)
    process_memory_info_dict : dict = field(default_factory=dict)
    process_memory_usage : int = None # 단위 : KB
    process_cpu_usgae : float = None

@dataclass
class PreprocessedProcessInfo:
    process_name : str = None
    process_pid : int = None
    process_owner : str = None
    process_owner_domain : str = None
    process_owner_type : int = None
    process_time_info_dict : dict = field(default_factory=dict)
    process_memory_info_dict : dict = field(default_factory=dict)
    process_memory_usage : int = None # 단위 : KB
    process_cpu_usgae : float = None
    live : bool = False

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

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [ ( "dwSize" , wintypes.DWORD) ,
                 ( "cntUsage" , wintypes.DWORD ),
                 ( "th32ProcessID" , wintypes.DWORD ),
                 ( "th32DefaultHeapID" , ctypes.POINTER((wintypes.ULONG)) ),
                 ( "th32ModuleID" , wintypes.DWORD ) ,
                 ( "cntThreads" , wintypes.DWORD ) ,
                 ( "th32ParentProcessID" , wintypes.DWORD ) ,
                 ( "pcPriClassBase" , wintypes.LONG ) ,
                 ( "dwFlags" , wintypes.DWORD ),
                 ( "szExeFile" , wintypes.CHAR * 260 ) ]

TH32CS_SNAPMODULE = 0x00000002
INVALID_HANDLE_VALUE = -1
CP_ACP = 0

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
        process_info.process_name = process_entry_32.szExeFile.decode("utf8")
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

            process_info.process_time_info_dict = win32process.GetProcessTimes(hProc)
            process_info.process_memory_info_dict = win32process.GetProcessMemoryInfo(hProc)

            win32api.CloseHandle(hToken)
            win32api.CloseHandle(hProc)

        except:
            process_info.process_owner = "Unknown"

        process_info_list.append(process_info)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.pointer(process_entry_32))

    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)

    return process_info_list

def preprocessing_process_info(prev_process_info_list : list[ProcessInfo], process_info_list : list[ProcessInfo]) -> list[PreprocessedProcessInfo]:
    perproceseed_process_info_list = []

    process_info_list.sort()
    prev_process_info_list.sort()

    i = 0
    j = 0

    for i in range(0, process_info_list.len()):
        perproceseed_process_info = PreprocessedProcessInfo()

        if process_info_list[i].process_pid == prev_process_info_list[i].process_pid and process_info_list[i].process_time_info_dict["CreationTime"] == prev_process_info_list[i].process_pid["CreationTime"] :
            perproceseed_process_info.process_memory_usage = process_info_list[i].process_memory_info_dict["WorkingSetSize"] / 1024.0

            prev_process_time = prev_process_info_list[i].process_pid["KernelTime"] + prev_process_info_list[i].process_pid["UserTime"]
            process_time = process_info_list[i].process_pid["KernelTime"] + process_info_list[i].process_pid["UserTime"]

    return None


def main():
    elevate.elevate(show_console = True)
    if set_privilege(win32con.SE_DEBUG_NAME) == False:
        print("error : can not set privilege")

    process_manager_update_time = 1

    prev_process_info_list = get_process_info_list()
    time.sleep(process_manager_update_time)

    while True:

        process_info_list = get_process_info_list()

        print("%-25.25s\t%-5s\t%-15.15s\t%-10.10s\t%12.12s" % ("name", "pid", "owner", "cpu_usage", "memory_usage"))
        for process_info in process_info_list:
            print("%-25.25s\t%-5d\t%- 15.15s\t%-10.10s\t%12.12s" % (process_info.process_name, process_info.process_pid, process_info.process_owner, "", (str(process_info.process_memory_usage) + " " + "K")))

        prev_process_info_list = process_info_list

        time.sleep(process_manager_update_time)
        break

    os.system("pause")

if __name__ == '__main__':
    main()