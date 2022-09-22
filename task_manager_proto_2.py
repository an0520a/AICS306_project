from multiprocessing import process
from shutil import ExecError
import sys
import win32api
import win32process
import win32con
import win32security
import winnt
import ctypes
from ctypes import wintypes
from ctypes import windll


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


# input value : https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
def set_privilege(szPrivilege):

    hToken = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_ADJUST_PRIVILEGES
    )
    # win32security.OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess)
        # Do it
            # 프로세스의 토큰 핸들을 획득한다.
        # Param
            # ProcessHandle : 프로세스 핸들
            # DesiredAccess : 토큰 접근 권한
        # return
            # 프로세스의 토큰을 반환 (Handle)

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
                # 특권이 명시된 구조체 LUID를 반환.

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
    print(win32api.GetLastError())

    win32api.CloseHandle(hToken)

def main():
    hProcessSnapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, None)
    process_entry_32 = PROCESSENTRY32()
    process_entry_32.dwSize = ctypes.sizeof(process_entry_32)

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.pointer(process_entry_32))

    print("%-25.25s\t%-5s\t%5.5s" % ("name", "pid", "owner"))
    while flag:
        process_name = process_entry_32.szExeFile.decode("utf8")
        process_pid = process_entry_32.th32ProcessID
        process_owner = ""
        process_owner_domain = ""
        try:
            hProc = win32api.OpenProcess(
                win32con.MAXIMUM_ALLOWED, win32con.FALSE,
                process_pid
            )
            
            hToken = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )

            token_user = win32security.GetTokenInformation(hToken, win32security.TokenOwner)
            process_owner, process_owner_domain, process_owner_type = win32security.LookupAccountSid(
                None, token_user
            )
            

        except:
            process_owner = "Unknown"

        print("%-25.25s\t%-5d\t%8.8s" % (process_name, process_pid, process_owner))
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.pointer(process_entry_32))

    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)

if __name__ == '__main__':
    main()