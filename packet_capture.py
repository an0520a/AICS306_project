import ctypes
from npcap_h import *
from ctypes import wintypes
from ctypes import windll
import win32con
import win32api
import numpy as np
import re
from dataclasses import dataclass
from dataclasses import field
from windows_h import *
from windivert_h import *
import atexit
import multiprocessing as mp
import signal

@dataclass
class ProcessPortInfo:
    tcp : set[np.uint16] = field(default_factory = set[np.uint16])
    udp : set[np.uint16] = field(default_factory = set[np.uint16])
    tcp6 : set[np.uint16] = field(default_factory = set[np.uint16])
    udp6 : set[np.uint16] = field(default_factory = set[np.uint16])
    timestamp : np.int64 = 0

windivertdll : ctypes.CDLL = ctypes.CDLL(r".\WinDivert\Lib\WinDivert.dll")
wpcapdll : ctypes.CDLL = ctypes.CDLL(WPCAP_DLL_PATH)

#pid must be int or set
def find_local_tcp_ports_by_pid(pid) -> set[np.uint16]:
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
                local_tcp_port_list.add(np.uint16(tcprow_owner_pid.dwLocalPort))
    elif type(pid) == set:
        for tcprow_owner_pid in tcprow_owner_pid_arr:
            if tcprow_owner_pid.dwOwningPid in pid:
                local_tcp_port_list.add(np.uint16(tcprow_owner_pid.dwLocalPort))
    
    return local_tcp_port_list



#pid must be int or set
def find_local_tcp6_ports_by_pid(pid) -> set[np.uint16]:
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
                local_tcp6_port_list.add(np.uint16(tcp6row_owner_pid.dwLocalPort))
    elif type(pid) == set:
        for tcp6row_owner_pid in tcp6row_owner_pid_arr:
            if tcp6row_owner_pid.dwOwningPid in pid:
                local_tcp6_port_list.add(np.uint16(tcp6row_owner_pid.dwLocalPort))
    
    return local_tcp6_port_list



#pid must be int or set
def find_local_udp_ports_by_pid(pid) -> set[np.uint16]:
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
                local_udp_port_list.add(np.uint16(udprow_owner_pid.dwLocalPort))
    elif type(pid) == set:
        for udprow_owner_pid in udprow_owner_pid_arr:
            if udprow_owner_pid.dwOwningPid in pid:
                local_udp_port_list.add(np.uint16(udprow_owner_pid.dwLocalPort))
    
    return local_udp_port_list



#pid be int or set
def find_local_udp6_ports_by_pid(pid : int) -> set[np.uint16]:
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
                local_udp_port_list.add(np.uint16(udp6row_owner_pid.dwLocalPort))
    elif type(pid) == set:
        for udp6row_owner_pid in udp6row_owner_pid_arr:
            if udp6row_owner_pid.dwOwningPid in pid:
                local_udp_port_list.add(np.uint16(udp6row_owner_pid.dwLocalPort))
    
    return local_udp_port_list


# 극단적으로 짧게 생성되어 죽는 프로세스에 대해서는 캡처를 할 수 없는 문제가 있음
# 이유 : pid로 프로세스프로세스 핸들을 통해 프로세스 이름을 얻는데, 이 과정중에 프로세스가 죽으면 프로세스 이름을 얻을 수 없게됨
def process_packet_caputre_by_process_name(interface_name : str, process_name : str, pcap_name : str, recv_pipe):
    windivert_addr = WINDIVERT_ADDRESS()
    process_path_by_pid_buffer = (wintypes.CHAR * win32con.MAX_PATH)()
    process_path_by_pid_size = 0
    process_name_by_pid : str = str()
    process_path_to_name_regex = re.compile(r'\\([^\\]*)$')
    process_port_info_arr = np.array([ProcessPortInfo])

    sub_packet_capture_process_recv_pipe, sub_packet_capture_process_send_pipe = mp.Pipe(False)
    sub_packet_capture_process = mp.Process(name="taskmanager packet sub catpure", target=packet_capture, args=(interface_name, pcap_name, sub_packet_capture_process_send_pipe))
    sub_packet_capture_process.start()

    if sub_packet_capture_process_recv_pipe.recv() == "Done":
        sub_packet_capture_process_recv_pipe.close()
    else:
        raise Exception("sub process error")

    process_port_info = ProcessPortInfo()

    measurement_time = wintypes.LARGE_INTEGER()
    ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(measurement_time))
    process_port_info.timestamp = np.int64(measurement_time)
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
        exit(1)

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.byref(process_entry_32))
    flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32)) # need to pass pid 0

    while flag:
        if process_entry_32.szExeFile.decode("UTF-8") == process_name:
            init_pid_set.add(process_entry_32.th32ProcessID)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32))
    
    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)

    process_port_info.tcp = find_local_tcp_ports_by_pid(init_pid_set)
    process_port_info.udp = find_local_udp_ports_by_pid(init_pid_set)
    process_port_info.tcp6 = find_local_tcp6_ports_by_pid(init_pid_set)
    process_port_info.udp6 = find_local_udp6_ports_by_pid(init_pid_set)
    process_port_info_arr = np.append(process_port_info_arr, process_port_info)

    print(process_port_info)

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
                    if windivert_addr.IPv6:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            process_port_info.tcp6.add(np.uint16(windivert_addr.Flow.LocalPort))
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            process_port_info.udp6.add(np.uint16(windivert_addr.Flow.LocalPort))
                    else:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            process_port_info.tcp.add(np.uint16(windivert_addr.Flow.LocalPort))
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            process_port_info.udp.add(np.uint16(windivert_addr.Flow.LocalPort))
                elif windivert_addr.Event == WINDIVERT_EVENT_FLOW_DELETED: 
                    if windivert_addr.IPv6:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            process_port_info.tcp6.remove(windivert_addr.Flow.LocalPort)
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            process_port_info.udp6.remove(windivert_addr.Flow.LocalPort)
                    else:
                        if windivert_addr.Flow.Protocol == IPPROTO_TCP:
                            process_port_info.tcp.remove(windivert_addr.Flow.LocalPort)
                        elif windivert_addr.Flow.Protocol == IPPROTO_UDP:
                            process_port_info.udp.remove(windivert_addr.Flow.LocalPort)
                
                process_port_info.timestamp = np.int64(windivert_addr.Timestamp)
                process_port_info_arr = np.append(process_port_info_arr, process_port_info)
                print(process_port_info)

        except Exception as e:
            print(process_port_info)
            print(int(windivert_addr.Flow.LocalPort))
            print("error : ", e)
            # raise Exception("error")

        if recv_pipe.poll():
            if recv_pipe.recv() == signal.SIGINT:
                sub_packet_capture_process.kill()
                sub_packet_capture_process.join()

                recv_pipe.close()

                if windivertdll.WinDivertClose(hFlowLayer) == False:
                    print("error_code : {}".format(win32api.GetLastError()))
                print("end")

                return

def packet_capture(interface_name : str, pcap_file_name : str = "tmp_pcap.pcap", send_pipe = None):
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

    if send_pipe:
        send_pipe.send("Done")
        send_pipe.close()

    wpcapdll.pcap_loop(pcap_device_handle, 0, callback_func, ctypes.cast(pcap_file, ctypes.POINTER(ctypes.c_ubyte)))

    wpcapdll.pcap_close(pcap_device_handle)


def py_packet_handler(dumpfile : ctypes.POINTER(ctypes.c_ubyte), header : ctypes.POINTER(pcap_pkthdr), pkt_data : ctypes.POINTER(ctypes.c_ubyte)):
    wpcapdll.pcap_dump(dumpfile, header, pkt_data)

# def main():
#         global wpcapdll
#         wpcapdll = ctypes.CDLL(WPCAP_DLL_PATH)

# process_packet_caputre_by_process_name("", "chrome.exe", "", None)