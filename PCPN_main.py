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
from npcap_h import *
from windows_h import *
import packet_capture
import multiprocessing as mp
import signal


from PyQt5.QtWidgets import *
from PyQt5 import uic
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore    import *

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

@dataclass(order=True)
class ProcessInfo:
    process_pid: int = None
    process_name: str = ""
    process_path: str = ""
    process_owner: str = ""
    process_owner_domain: str = ""
    process_owner_type: int = None
    process_path: str = ""
    process_time_info_dict: dict = field(default_factory=dict)
    process_memory_info_dict: dict = field(default_factory=dict)
    measurement_time: wintypes.LARGE_INTEGER = wintypes.LARGE_INTEGER()
    token_flag: bool = False


@dataclass(order=True)
class PreprocessedProcessInfo(ProcessInfo):
    process_memory_usage: float = 0  # 단위 : KB
    process_cpu_usage_rate: float = 0
    process_memory_usage_rate: float = 0


@dataclass
class HardSystemMemoryInfo:  # 변동되지 않는 메모리 정보
    kInstall: int = None
    kHardwareReserved: int = None
    kTotal: int = None


@dataclass
class SoftSystemMemoryInfo:  # 변동되는 메모리 정보
    available: int = None


@dataclass
class SystemMemoryInfo:
    hard_system_memory_info: HardSystemMemoryInfo = field(default_factory=dataclass)
    soft_system_memory_info: SoftSystemMemoryInfo = field(default_factory=dataclass)


@dataclass(order=True)
class InterfaceInfo:
    name: str = ""
    description: str = ""


FREQUENCY = wintypes.LARGE_INTEGER()
NUMBER_OF_PROCESS = 0
libcdll: ctypes.CDLL
packetdll: ctypes.CDLL
wpcapdll: ctypes.CDLL
encode_type : str = str("ISO-8859-1")

#0:process_name
#1:process_pid
#2:process_owner
#3:process_cpu_usage_rate
#4:process_memory_usage
#5:process_momory_usage_rate
sort_key : int = int(1)


def kill_process(process_pid):
    try:
        hProc = win32api.OpenProcess(
            win32con.PROCESS_TERMINATE, win32con.FALSE,
            process_pid
        )
        win32api.TerminateProcess(hProc, 1)
        win32api.CloseHandle(hProc)
    except:
        ctypes.windll.User32.MessageBoxW(None, "작업을 완료하지 못했습니다 : 액세스가 거부되었습니다.", "Error", MB_ICONERROR | MB_OK)

def EnumWindowProc(hWnd, lParam):
    if win32gui.GetParent(hWnd) == None:
        pid = 0
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
def set_privilege(szPrivilege: str):
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
def get_process_info_list() -> list[ProcessInfo]:
    process_info_list = []
    hProcessSnapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, None)
    process_entry_32 = PROCESSENTRY32()
    process_entry_32.dwSize = ctypes.sizeof(process_entry_32)

    if hProcessSnapshot == INVALID_HANDLE_VALUE:
        print("error_code : {}".format(win32api.GetLastError()))
        raise Exception("error_code : {}".format(win32api.GetLastError()))

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.byref(process_entry_32))
    flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32))  # need to pass pid 0

    while flag:
        process_info = ProcessInfo()
        process_info.process_name = process_entry_32.szExeFile.decode(encode_type)
        process_info.process_pid = process_entry_32.th32ProcessID

        hProc = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, win32con.FALSE,
                                                   process_info.process_pid)

        if hProc == INVALID_HANDLE_VALUE:
            print("error_code : {}".format(win32api.GetLastError()))
            raise Exception("error_code : {}".format(win32api.GetLastError()))

        try:
            hToken = win32security.OpenProcessToken(
                hProc,
                win32con.TOKEN_QUERY
            )

            token_user = win32security.GetTokenInformation(hToken, win32security.TokenOwner)
            process_info.process_owner, process_info.process_owner_domain, process_info.process_owner_type = \
                win32security.LookupAccountSid(
                    None, token_user
                )
            win32api.CloseHandle(hToken)
        except:
            process_info.process_owner = "SYSTEM"

        exe_name_size = wintypes.DWORD(win32con.MAX_PATH + 1)
        exe_name = (wintypes.CHAR * exe_name_size.value)()
        ctypes.windll.kernel32.QueryFullProcessImageNameA(hProc.__int__(), 0, ctypes.byref(exe_name),
                                                          ctypes.byref(exe_name_size))

        process_info.process_path = str(exe_name.value.decode(encode_type))

        # process_info.process_time_info_dict = win32process.GetProcessTimes(hProc)
        # process_info.process_memory_info_dict = win32process.GetProcessMemoryInfo(hProc)
        CreationTime = wintypes.LARGE_INTEGER()
        ExitTime = wintypes.LARGE_INTEGER()
        KernelTime = wintypes.LARGE_INTEGER()
        UserTime = wintypes.LARGE_INTEGER()

        windll.kernel32.GetProcessTimes(hProc, ctypes.byref(CreationTime), ctypes.byref(ExitTime), ctypes.byref(KernelTime), ctypes.byref(UserTime))
        process_info.process_time_info_dict = { "CreationTime" : CreationTime.value, "ExitTime" : ExitTime.value, "KernelTime" : KernelTime.value, "UserTime" : UserTime.value }

        process_memory_counter = PROCESS_MEMORY_COUNTERS()

        windll.psapi.GetProcessMemoryInfo(hProc, ctypes.byref(process_memory_counter), ctypes.sizeof(process_memory_counter))
        process_info.process_memory_info_dict = \
        {
            "cb" : process_memory_counter.cb,
            "PageFaultCount" : process_memory_counter.PageFaultCount ,
            "PeakWorkingSetSize" : process_memory_counter.PeakWorkingSetSize ,
            "WorkingSetSize" : process_memory_counter.WorkingSetSize ,
            "QuotaPeakPagedPoolUsage" : process_memory_counter.QuotaPeakPagedPoolUsage ,
            "QuotaPagedPoolUsage" : process_memory_counter.QuotaPagedPoolUsage ,
            "QuotaPeakNonPagedPoolUsage" : process_memory_counter.QuotaPeakNonPagedPoolUsage ,
            "QuotaNonPagedPoolUsage" : process_memory_counter.QuotaNonPagedPoolUsage ,
            "PagefileUsage" : process_memory_counter.PagefileUsage ,
            "PeakPagefileUsage" : process_memory_counter.PeakPagefileUsage
        }

        measurement_time = wintypes.LARGE_INTEGER()
        ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(measurement_time))
        process_info.measurement_time = measurement_time
        process_info.token_flag = True

        win32api.CloseHandle(hProc)

        process_info_list.append(process_info)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32))

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
    ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(performance_information),
                                           ctypes.sizeof(performance_information))
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


def preprocessing_process_info(prev_process_info_list: list[ProcessInfo], process_info_list: list[ProcessInfo]) -> list[
    PreprocessedProcessInfo]:
    preprocessed_process_info_list = []

    process_info_list.sort()
    prev_process_info_list.sort()

    i = 0
    j = 0

    kTotalMemorySize = get_hard_system_memory_info().kTotal

    process_info_list_len = len(process_info_list)
    prev_process_info_list_len = len(prev_process_info_list)

    def process_info_list_to_pre_processed_process_info(_preprocessed_process_info: PreprocessedProcessInfo,
                                                        _process_info: ProcessInfo):
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

        if process_info_list[i].token_flag and prev_process_info_list[j].token_flag:
            if process_info_list[i].process_pid == prev_process_info_list[j].process_pid:
                if process_info_list[i].process_time_info_dict["CreationTime"] == \
                        prev_process_info_list[j].process_time_info_dict["CreationTime"]:
                    process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                    preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict[
                                                                         "WorkingSetSize"] / 1024.0
                    preprocessed_process_info.process_memory_usage_rate = (100 *
                                                                           preprocessed_process_info.process_memory_info_dict[
                                                                               "WorkingSetSize"]) / kTotalMemorySize

                    process_time = process_info_list[i].process_time_info_dict["KernelTime"] + \
                                   process_info_list[i].process_time_info_dict["UserTime"]
                    prev_process_time = prev_process_info_list[j].process_time_info_dict["KernelTime"] + \
                                        prev_process_info_list[j].process_time_info_dict["UserTime"]
                    elapsed_100nanoseconds = process_info_list[i].measurement_time.value - prev_process_info_list[
                        j].measurement_time.value
                    elapsed_100nanoseconds *= 100000  # change unit.
                    elapsed_100nanoseconds /= FREQUENCY.value
                    preprocessed_process_info.process_cpu_usage_rate = (process_time - prev_process_time) / (
                                elapsed_100nanoseconds * NUMBER_OF_PROCESS)
                    preprocessed_process_info_list.append(preprocessed_process_info)

                else:  # 새로운 프로세스가 생긴 케이스 (기존 프로세스와 pid가 같음)
                    process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                    preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict[
                                                                         "WorkingSetSize"] / 1024.0
                    preprocessed_process_info.process_memory_usage_rate = \
                    preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / kTotalMemorySize

                    preprocessed_process_info.process_cpu_usage_rate = 0

                    preprocessed_process_info_list.append(preprocessed_process_info)

            else:
                if process_info_list[i].process_pid < prev_process_info_list[
                    j].process_pid:  # 새로운 프로세스가 생긴 케이스 (기존 프로세스와 pid가 다름)
                    while process_info_list[i].process_pid < prev_process_info_list[j].process_pid:
                        process_info_list_to_pre_processed_process_info(preprocessed_process_info, process_info_list[i])

                        preprocessed_process_info.process_memory_usage = \
                        preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / 1024.0
                        preprocessed_process_info.process_memory_usage_rate = \
                        preprocessed_process_info.process_memory_info_dict["WorkingSetSize"] / kTotalMemorySize

                        preprocessed_process_info.process_cpu_usage_rate = 0

                        preprocessed_process_info_list.append(preprocessed_process_info)

                        i += 1

                    continue

                if process_info_list[i].process_pid > prev_process_info_list[j].process_pid:
                    while process_info_list[i].process_pid > prev_process_info_list[j].process_pid:  # 있던 프로세스가 죽은 케이스
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
                    while process_info_list[i].process_pid > prev_process_info_list[j].process_pid:  # 있던 프로세스가 죽은 케이스
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

            preprocessed_process_info.process_memory_usage = preprocessed_process_info.process_memory_info_dict[
                                                                 "WorkingSetSize"] / 1024.0
            preprocessed_process_info.process_memory_usage_rate = preprocessed_process_info.process_memory_info_dict[
                                                                      "WorkingSetSize"] / kTotalMemorySize

            preprocessed_process_info.process_cpu_usage_rate = 0
        else:
            preprocessed_process_info.process_name = process_info_list[k].process_name
            preprocessed_process_info.process_pid = process_info_list[k].process_pid

        preprocessed_process_info_list.append(preprocessed_process_info)

    return preprocessed_process_info_list


def get_interface_info_list() -> list[InterfaceInfo]:
    error_buf = (ctypes.c_char * PCAP_ERRBUF_SIZE)()
    interface_info_list: list = []

    all_device_linked_list = ctypes.POINTER(pcap_if_t)()
    device = ctypes.POINTER(pcap_if_t)()

    if wpcapdll.pcap_findalldevs_ex(PCAP_SRC_IF_STRING, None, ctypes.byref(all_device_linked_list),
                                    ctypes.byref(error_buf)) == -1:
        raise Exception("Error in pcap_findalldevs_ex: ", error_buf.value)

    device = all_device_linked_list
    while device:
        device_info = InterfaceInfo()
        device_info.name = str(device.contents.name.decode(encode_type))
        device_info.description = str(device.contents.description.decode(encode_type))
        interface_info_list.append(device_info)
        device = device.contents.next

    wpcapdll.pcap_freealldevs(all_device_linked_list)

    return interface_info_list


def start_process_packet_caputre_by_process_name(interface_name: str, process_name: str, pcap_name: str) -> tuple:
    recv_pipe, send_pipe = mp.Pipe(False)
    sub_packet_capture_process = mp.Process(name="PCPN process packet capture manager",
                                            target=packet_capture.process_packet_caputre_by_process_name,
                                            args=(interface_name, process_name, pcap_name, recv_pipe))
    sub_packet_capture_process.start()
    return (sub_packet_capture_process, send_pipe)


# process_packet_caputre_by_process_name을 join 한다.
# dpkt 부분의 병목으로 상당히 시간이 걸린다.
# join 되는동안 main 프로세스는 block 된다.
def join_process_packet_caputre_by_process_name(process_pipe_tuple: tuple) -> None:
    process_pipe_tuple[1].send(signal.SIGINT)
    process_pipe_tuple[1].close()
    process_pipe_tuple[0].join()
    ctypes.windll.User32.MessageBoxW(None, "성공적으로 캡처가 완료되었습니다.", "성공", MB_ICONINFORMATION | MB_OK)


# def end_process_packet_caputre_by_process_name(sub_packet_capture_process : mp.Process) -> None:

def global_init() -> None:
    global NUMBER_OF_PROCESS
    global FREQUENCY
    global packetdll
    global wpcapdll
    global libcdll
    global encode_type

    packetdll = ctypes.CDLL(PACKET_DLL_PATH)
    wpcapdll = ctypes.CDLL(WPCAP_DLL_PATH)
    libcdll = ctypes.CDLL("msvcrt.dll")
    # encode_type = sys.getdefaultencoding()

    system_info = SYSTEM_INFO()
    ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(system_info))
    NUMBER_OF_PROCESS = system_info.dwNumberOfProcessors
    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(FREQUENCY))


def dependency_check():
    exit_flag: bool = False

    if os.path.isfile(PACKET_DLL_PATH) == False:
        ctypes.windll.User32.MessageBoxW(None, "he program can't start because Packet.dll is missing from your computer.", "Error", MB_ICONERROR | MB_OK)
        exit_flag = True

    if os.path.isfile(WPCAP_DLL_PATH) == False:
        ctypes.windll.User32.MessageBoxW(None, "The program can't start because wpcap.dll is missing from your computer", "Error", MB_ICONERROR | MB_OK)
        exit_flag = True

    if os.path.isfile(resource_path(r".\Lib\WinDivert.dll")) == False:
        ctypes.windll.User32.MessageBoxW(None, "The program can't start because WinDivert.dll is missing from your computer", "Error", MB_ICONERROR | MB_OK)
        exit_flag = True


    if exit_flag:
        raise Exception("missing dll")


#-------------------------------MAINMAIN------------------------------------------

form = resource_path('test.ui')
form_class = uic.loadUiType(form)[0]


#first ui to check network interface card number
class WindowClass(QMainWindow, form_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # btn_test 클릭 시 testclick 함수 실행
        self.button_event.clicked.connect(self.btn_event)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.button_event.setText(_translate("MainWindow", "선택"))

        interface_info_list = get_interface_info_list()
        for interface_number, interface_info in enumerate(interface_info_list):
            self.listWidget.insertItem(interface_number, str(interface_number) + " : " + interface_info.description)

        self.listWidget.itemSelectionChanged.connect(self.changed)
        self.listWidget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def btn_event(self):
        list_item = self.listWidget.selectedIndexes()
        for item in list_item:
            interface_number = item.row()
        #to second ui
        self.close()
        self.window_2 = second(interface_number)
        self.window_2.exec()  # 두번째 창을 닫을 때 까지 기다림
        sys.exit()

    def changed(self):#선택
        list_item = self.listWidget.selectedIndexes()

# ------------------------------------------------------------------------------------------------


form2 = resource_path('test2.ui')
form2_class = uic.loadUiType(form2)[0]

# first ui to check network interface card number
class second(QDialog, form2_class):
    def __init__(self, interface_number):
        super().__init__()
        self.interface_number = interface_number
        self.prev_process_info_list = get_process_info_list()
        self.setupUi(self)

        self.my_qtimer = QTimer(self)
        self.my_qtimer.timeout.connect(self.table_print)
        self.my_qtimer.start(1000)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        item = self.tableWidget.horizontalHeaderItem(0)
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Dialog", "이름"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Dialog", "PID"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("Dialog", "소유자"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("Dialog", "CPU 사용률(%)"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("Dialog", "메모리 사용량"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("Dialog", "메모리 사용률(%)"))

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.pushButton.setText(_translate("Dialog", "kill"))
        self.pushButton_2.setText(_translate("Dialog", "Capture Start"))
        self.pushButton_4.setText(_translate("Dialog", "Capture Stop"))
        self.pushButton_2.setDisabled(True)
        self.pushButton_4.setDisabled(True)
        self.label.setText(_translate("Dialog", "Process Name"))
        self.label_2.setText(_translate("Dialog", "PID"))
        self.label_3.setText(_translate("Dialog", "Save Path"))
        self.lineEdit.setText(_translate("Dialog", "tmp.pcap"))
        Dialog.setWindowTitle("PCPN")
        self.textEdit_3.setText(" ")
        self.textEdit_5.setText(" ")
        # ---------------------------------ACTION FUNCTIONS----------------------------
        self.tableWidget.cellClicked.connect(self.cellclicked_event)
        self.pushButton.clicked.connect(self.process_kill)
        self.pushButton_2.clicked.connect(self.capture_start)
        self.pushButton_4.clicked.connect(self.capture_stop)
        self.tableWidget.horizontalHeader().sectionClicked.connect(self.myheader_clicked)
        # ------------------------------------------------------------------------------
        interface_info_list = get_interface_info_list()
        self.interface_name = interface_info_list[self.interface_number].name
        self.table_print()

    #sorting function
    def myheader_clicked(self, logicalIndex):
        global sort_key
        sort_key = logicalIndex
        self.table_print()

    #table printing function
    def table_print(self):
        #table calculation
        process_info_list = get_process_info_list()
        preprocessed_process_info_list = preprocessing_process_info(self.prev_process_info_list, process_info_list)
        #0:process_name
        #1:process_pid
        #2:process_owner
        #3:process_cpu_usage_rate
        #4:process_memory_usage
        #5:process_momory_usage_rate
        if sort_key == 0:
            preprocessed_process_info_list.sort(key=lambda x:x.process_name)
        elif sort_key == 1:
            preprocessed_process_info_list.sort(key=lambda x:x.process_pid)
        elif sort_key == 2:
            preprocessed_process_info_list.sort(key=lambda x:x.process_owner)
        elif sort_key == 3:
            preprocessed_process_info_list.sort(key=lambda x:x.process_cpu_usage_rate)
        elif sort_key == 4:
            preprocessed_process_info_list.sort(key=lambda x:x.process_memory_usage)
        elif sort_key == 5:
            preprocessed_process_info_list.sort(key=lambda x:x.process_memory_usage_rate)

        self.prev_process_info_list = process_info_list

        #table printing
        self.tableWidget.setRowCount(0)
        process_cnt = 0

        for process_info in preprocessed_process_info_list:
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(process_cnt, 0, QTableWidgetItem(str(process_info.process_name)))
            self.tableWidget.setItem(process_cnt, 1, QTableWidgetItem(str(process_info.process_pid)))
            self.tableWidget.setItem(process_cnt, 2, QTableWidgetItem(str(process_info.process_owner)))
            self.tableWidget.setItem(process_cnt, 3,
                                     QTableWidgetItem(str(round(process_info.process_cpu_usage_rate, 2)) + "%"))
            self.tableWidget.setItem(process_cnt, 4,
                                     QTableWidgetItem(str(int(process_info.process_memory_usage)) + " " + "K"))
            self.tableWidget.setItem(process_cnt, 5,
                                     QTableWidgetItem(str(round(process_info.process_memory_usage_rate, 2)) + "%"))
            process_cnt += 1
            
        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.pid_all = self.textEdit_5.toPlainText()
        self.process_name_all = self.textEdit_3.toPlainText()


    def cellclicked_event(self, row, col):
        x = self.tableWidget.selectedIndexes() # 리스트로 선택된 행번호와 열번호가 x에 입력된다.
        x[0].row() #첫번째 선택된 행번호를 부르는 방법
        x[0].column() #첫번째 선택된 열번호를 부르는 방법
        print(x[0].column())
        if self.pushButton_2.text() == "Capturing":
            None
        else:
            self.pushButton_2.setEnabled(True)
            self.textEdit_3.setText(" ")
            self.textEdit_5.setText(" ")
            process_id = self.tableWidget.item(row, 1)
            process_name = self.tableWidget.item(row, 0)
            self.textEdit_3.setText(process_name.text())
            self.textEdit_5.setText(process_id.text())

    def process_kill(self, row):
        pid = self.textEdit_5.toPlainText()
        kill_process(int(pid))

    def capture_start(self):
        process_name = self.textEdit_3.toPlainText()
        save_path = self.lineEdit.text()

        hFile = ctypes.windll.kernel32.CreateFileW(
            save_path, 
            win32con.GENERIC_WRITE, 
            win32con.FILE_SHARE_WRITE, 
            None,
            win32con.CREATE_NEW,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None
        )

        if hFile == INVALID_HANDLE_VALUE:
            ec = win32api.GetLastError()
            
            if ec == ERROR_FILE_EXISTS:
                id = ctypes.windll.User32.MessageBoxW(None, "파일이 이미 존재합니다. 덮어쓰겠습니까?", "확인", MB_ICONWARNING | MB_YESNO)
                if id != IDYES:
                    return
                else:
                    hFile = ctypes.windll.kernel32.CreateFileW(
                        save_path, 
                        win32con.GENERIC_WRITE, 
                        win32con.FILE_SHARE_WRITE, 
                        None,
                        win32con.CREATE_ALWAYS,
                        win32con.FILE_ATTRIBUTE_NORMAL,
                        None
                    )

                    if hFile == INVALID_HANDLE_VALUE:
                        ctypes.windll.User32.MessageBoxW(None, "액세스가 거부되었습니다.", "Error", MB_ICONERROR | MB_OK)
                        return
            else:
                ctypes.windll.User32.MessageBoxW(
                    None, 
                    "지원되지 않는 경로이거나 액세스가 거부되었습니다.\nerror_code: {}".format(win32api.GetLastError()), 
                    "Error", 
                    MB_ICONERROR | MB_OK
                )
                return

        ctypes.windll.kernel32.CloseHandle(hFile)
        ctypes.windll.kernel32.DeleteFileW(save_path)

        self.pushButton_4.setEnabled(True)
        self.pushButton_2.setDisabled(True)
        self.pushButton_2.setText("Capturing")

        self.process_pipe_tuple = start_process_packet_caputre_by_process_name(self.interface_name, process_name, save_path)

    def capture_stop(self):
        if self.pushButton_2.setText != "Capturing":
            self.pushButton_4.setDisabled(True)
        print("stop")
        process_name = self.textEdit_3.toPlainText()
        self.pushButton_2.setEnabled(True)
        self.pushButton_2.setText("Capture Start")
        join_process_packet_caputre_by_process_name(self.process_pipe_tuple)


# ------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    # elevate.elevate(show_console = True)
    mp.freeze_support()
    
    if not is_admin():
        print("error : not admin", file=sys.stderr)
        ctypes.windll.User32.MessageBoxW(None, "관리자 권한으로 실행해야 합니다.", "Error", MB_ICONERROR | MB_OK)
        raise Exception("관리자 권한으로 실행해야 합니다.")
    if set_privilege(win32con.SE_DEBUG_NAME) == False:
        ctypes.windll.User32.MessageBoxW(None, "권한 상승이 실패했습니다.", "Error", MB_ICONERROR | MB_OK)
        raise Exception("권한 상승이 실패했습니다.")
    dependency_check()
    global_init()

    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_EnableHighDpiScaling)
    myWindow = WindowClass()
    myWindow.show()
    app.exec_()