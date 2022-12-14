import os
import sys
import ctypes
from npcap_h import *
from ctypes import wintypes
from ctypes import windll
import win32con
import win32api
import numpy as np
import re
import dataclasses
from dataclasses import dataclass
from dataclasses import field
from windows_h import *
from windivert_h import *
import multiprocessing as mp
import signal
import copy
import dpkt

@dataclass(order=True)
class ProcessPortInfo:
    tcp : set[np.uint16] = field(default_factory = set[np.uint16])
    udp : set[np.uint16] = field(default_factory = set[np.uint16])
    tcp6 : set[np.uint16] = field(default_factory = set[np.uint16])
    udp6 : set[np.uint16] = field(default_factory = set[np.uint16])
    timestamp : np.int64 = 0

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

windivertdll : ctypes.CDLL = ctypes.CDLL(resource_path(r".\Lib\WinDivert.dll"))
wpcapdll : ctypes.CDLL = ctypes.CDLL(WPCAP_DLL_PATH)
encode_type : str = str("ISO-8859-1")

# def global_init():
#     global encode_type
#     encode_type = sys.getdefaultencoding()

# global_init()


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
        raise Exception("error_code : {}".format(win32api.GetLastError()))

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
        raise Exception("error_code : {}".format(win32api.GetLastError()))

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
        raise Exception("error_code : {}".format(win32api.GetLastError()))

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
        raise Exception("error_code : {}".format(win32api.GetLastError()))

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

# ip ????????? ??????
# ??????????????? ?????? ???????????? ?????? ??????????????? ???????????? ????????? ??? ??? ?????? ????????? ??????
# ?????? : pid??? ???????????????????????? ????????? ?????? ???????????? ????????? ?????????, ??? ???????????? ??????????????? ????????? ???????????? ????????? ?????? ??? ?????????
# ???????????? udp 5353?????? ?????? ????????? ??????. udp 5353 ????????? ?????? ?????? ???????????? ???????????? ?????????, ?????? ?????? ???????????? ??????
def process_packet_caputre_by_process_name(interface_name : str, process_name : str, pcap_name : str, recv_pipe):
    print("Test")
    windivert_addr = WINDIVERT_ADDRESS()
    process_path_by_pid_buffer = (wintypes.CHAR * (win32con.MAX_PATH + 1))()
    tmp_path = (wintypes.WCHAR * (win32con.MAX_PATH + 1))()
    tmp_path_size = wintypes.DWORD(win32con.MAX_PATH + 1)
    tmp_file = (wintypes.WCHAR * (win32con.MAX_PATH + 1))()
    process_path_by_pid_size = 0
    process_name_by_pid : str = str()
    process_path_to_name_regex = re.compile(r'\\([^\\]*)$')
    process_port_info = ProcessPortInfo()
    process_port_info_arr = np.array([])
    flag_first_established_event : bool = False
    first_established_event_arr_index : int = 0
    first_established_event : WINDIVERT_ADDRESS = WINDIVERT_ADDRESS()

    if ctypes.windll.kernel32.GetTempFileNameW(".", "pcap", 0, ctypes.byref(tmp_file)) == 0:
        ctypes.windll.User32.MessageBoxW(None, "?????? ?????? ????????? ????????? ??? ????????????.", "Error", MB_ICONERROR | MB_OK)
        raise Exception("?????? ?????? ????????? ????????? ??? ????????????.")

    tmp_file = tmp_file.value
    
    # file_len = ctypes.windll.kernel32.WideCharToMultiByte(CP_ACP, 0, ctypes.byref(tmp_file), -1, None, 0, None, None)
    # ctypes.windll.kernel32.WideCharToMultiByte(CP_ACP, 0, ctypes.byref(tmp_file), -1, file_len, 0, None, None)
    # tmp_p = ctypes.cast(ctypes.byref(tmp_file), ctypes.c_char_p)

    packet_dump_this_conn, packet_dump_child_conn = mp.Pipe(True)
    sub_packet_capture_process = mp.Process(name="PCPN packet dump", target=packet_capture, args=(interface_name, tmp_file, packet_dump_child_conn))
    sub_packet_capture_process.start()

    if packet_dump_this_conn.recv() == "Done":
        measurement_time = wintypes.LARGE_INTEGER()
        ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(measurement_time))
        process_port_info.timestamp = np.int64(measurement_time)
        
        packet_dump_this_conn.send(True)
        packet_dump_this_conn.close()
    else:
        ctypes.windll.User32.MessageBoxW(None, "?????? ?????? ????????? ????????? ??? ????????????.", "Error", MB_ICONERROR | MB_OK)
        sub_packet_capture_process.kill()
        sub_packet_capture_process.join()
        raise Exception("?????? ?????? ????????? ????????? ??? ????????????.")

    #hFlowLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)
    hFlowLayer : wintypes.HANDLE = windivertdll.WinDivertOpen(b"!loopback", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)

    if hFlowLayer == INVALID_HANDLE_VALUE:
        ctypes.windll.User32.MessageBoxW(None, "error_code : {}".format(win32api.GetLastError()), "Error", MB_ICONERROR | MB_OK)
        sub_packet_capture_process.kill()
        sub_packet_capture_process.join()
        raise Exception("error_code : {}".format(win32api.GetLastError()))

    init_pid_set : set = set()
    hProcessSnapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, None)
    process_entry_32 = PROCESSENTRY32()
    process_entry_32.dwSize = ctypes.sizeof(process_entry_32)

    if hProcessSnapshot == INVALID_HANDLE_VALUE:
        ctypes.windll.User32.MessageBoxW(None, "error_code : {}".format(win32api.GetLastError()), "Error", MB_ICONERROR | MB_OK)
        sub_packet_capture_process.kill()
        sub_packet_capture_process.join()
        raise Exception("error_code : {}".format(win32api.GetLastError()))

    flag = windll.kernel32.Process32First(hProcessSnapshot, ctypes.byref(process_entry_32))
    flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32)) # need to pass pid 0

    while flag:
        if process_entry_32.szExeFile.decode(encode_type) == process_name:
            init_pid_set.add(process_entry_32.th32ProcessID)
        flag = windll.kernel32.Process32Next(hProcessSnapshot, ctypes.byref(process_entry_32))
    
    if hProcessSnapshot != INVALID_HANDLE_VALUE:
        ctypes.windll.kernel32.CloseHandle(hProcessSnapshot)

    process_port_info.tcp = find_local_tcp_ports_by_pid(init_pid_set)
    process_port_info.udp = find_local_udp_ports_by_pid(init_pid_set)
    process_port_info.tcp6 = find_local_tcp6_ports_by_pid(init_pid_set)
    process_port_info.udp6 = find_local_udp6_ports_by_pid(init_pid_set)
    process_port_info_arr = np.append(process_port_info_arr, copy.deepcopy(process_port_info))

    # print(process_port_info)

    while True:
        if windivertdll.WinDivertRecv(hFlowLayer, None, 0, None, ctypes.byref(windivert_addr)) == False:
            ctypes.windll.User32.MessageBoxW(None, "error_code : {}".format(win32api.GetLastError()), "Error", MB_ICONERROR | MB_OK)
            sub_packet_capture_process.kill()
            sub_packet_capture_process.join()
            raise Exception("error_code : {}".format(win32api.GetLastError()))


        hProc : wintypes.HANDLE = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, win32con.FALSE, windivert_addr.Flow.ProcessId)

        if hProc == INVALID_HANDLE_VALUE:
            ctypes.windll.User32.MessageBoxW(None, "error_code : {}".format(win32api.GetLastError()), "Error", MB_ICONERROR | MB_OK)
            sub_packet_capture_process.kill()
            sub_packet_capture_process.join()
            raise Exception("error_code : {}".format(win32api.GetLastError()))

        
        process_path_size = wintypes.DWORD(win32con.MAX_PATH + 1)
        if ctypes.windll.kernel32.QueryFullProcessImageNameA(hProc, 0, ctypes.byref(process_path_by_pid_buffer), ctypes.byref(process_path_size)) == False:
            # print("error_code : {}".format(win32api.GetLastError()))
            # raise Exception("3")
            process_name_by_pid = None

        ctypes.windll.kernel32.CloseHandle(hProc)

        regex_result = process_path_to_name_regex.search(process_path_by_pid_buffer.value.decode(encode_type))
        if regex_result != None:
            process_name_by_pid = regex_result.group(1)

        # print(process_name_by_pid)

        try:
            if process_name_by_pid == process_name:
                # print("pass")
                new_process_port_info = dataclasses.replace(process_port_info)
                first_established_event_arr_index = process_port_info_arr.size
                
                if windivert_addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED:
                    if (not flag_first_established_event) and (windivert_addr.Flow.Protocol == IPPROTO_TCP or windivert_addr.Flow.Protocol == IPPROTO_UDP):
                        first_established_event = copy.deepcopy(windivert_addr)
                        flag_first_established_event = True

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
                process_port_info_arr = np.append(process_port_info_arr, copy.deepcopy(process_port_info))
                # print(process_port_info)

        except Exception as e:
            pass
            # print(process_port_info)
            # print(int(windivert_addr.Flow.LocalPort))
            # print("error : ", e)
            # raise Exception("error")

        if recv_pipe.poll():
            if recv_pipe.recv() == signal.SIGINT:
                recv_pipe.close()

                if windivertdll.WinDivertClose(hFlowLayer) == False:
                    print("error_code : {}".format(win32api.GetLastError()))
                # print("end")

                sub_packet_capture_process.kill()
                sub_packet_capture_process.join()

                # for i in range(0, process_port_info_arr.size):
                #     print(process_port_info_arr[i].timestamp)

                input_pcap_file = open(tmp_file, "rb")
                writer_pcap_file = open(pcap_name, "wb+")

                reader = dpkt.pcap.Reader(input_pcap_file)
                writer = dpkt.pcap.Writer(writer_pcap_file)
                first_timestamp = 0
                find_timestamp = 0
                filter_index = 0

                if flag_first_established_event:
                    
                    windivert_addr = first_established_event

                    for timestamp, pkt in reader:
                        eth = dpkt.ethernet.Ethernet(pkt)

                        if eth.type == dpkt.ethernet.ETH_TYPE_IP and not windivert_addr.IPv6:
                            ip = eth.data

                            if (ip.p == dpkt.ip.IP_PROTO_TCP and windivert_addr.Flow.Protocol == IPPROTO_TCP) or (ip.p == dpkt.ip.IP_PROTO_UDP and windivert_addr.Flow.Protocol == IPPROTO_UDP):
                                if int.from_bytes(ip.src, "big") == windivert_addr.Flow.LocalAddr[0]:
                                    if int.from_bytes(ip.dst, "big") == windivert_addr.Flow.RemoteAddr[0] and ip.data.sport == windivert_addr.Flow.LocalPort and ip.data.dport == windivert_addr.Flow.RemotePort:
                                        find_timestamp = timestamp
                                        # print("Find")
                                        break
                                if int.from_bytes(ip.dst, "big") == windivert_addr.Flow.LocalAddr[0]:
                                    if int.from_bytes(ip.src, "big") == windivert_addr.Flow.RemoteAddr[0] and ip.data.dport == windivert_addr.Flow.LocalPort and ip.data.sport == windivert_addr.Flow.RemotePort:
                                        find_timestamp = timestamp
                                        # print("Find")
                                        break
    
                                    
                        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6 and windivert_addr.IPv6:
                            ip = eth.data
                            local_addr = windivert_addr.Flow.LocalAddr[0] << 96 | windivert_addr.Flow.LocalAddr[1] << 64 | windivert_addr.Flow.LocalAddr[2] << 32 | windivert_addr.Flow.LocalAddr[3]
                            remote_addr = windivert_addr.Flow.RemoteAddr[0] << 96 | windivert_addr.Flow.RemoteAddr[1] << 64 | windivert_addr.Flow.RemoteAddr[2] << 32 | windivert_addr.Flow.RemoteAddr[3]

                            if (ip.p == dpkt.ip.IP_PROTO_TCP and windivert_addr.Flow.Protocol == IPPROTO_TCP) or (ip.p == dpkt.ip.IP_PROTO_UDP and windivert_addr.Flow.Protocol == IPPROTO_UDP):
                                if int.from_bytes(ip.src, "big") == local_addr:
                                    if int.from_bytes(ip.dst, "big") == remote_addr and ip.data.sport == windivert_addr.Flow.LocalPort and ip.data.dport == windivert_addr.Flow.RemotePort:
                                        find_timestamp = timestamp
                                        # print("Find")
                                        break
                                if int.from_bytes(ip.dst, "big") == local_addr:
                                    if int.from_bytes(ip.src, "big") == remote_addr and ip.data.dport == windivert_addr.Flow.LocalPort and ip.data.sport == windivert_addr.Flow.RemotePort:
                                        find_timestamp = timestamp
                                        # print("Find")
                                        break


                    frequency = wintypes.LARGE_INTEGER()
                    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))

                    for i in range(0, process_port_info_arr.size):
                        process_port_info_arr[i].timestamp = np.float64((process_port_info_arr[i].timestamp) / np.int64(frequency))
                        process_port_info_arr[i].timestamp = process_port_info_arr[i].timestamp

                    during_time = np.float64((windivert_addr.Timestamp * 1000000) / np.int64(frequency))
                    during_time = during_time / np.float64(1000000)
                    during_time = find_timestamp - during_time
                    # print(during_time)
                            
                    for i in range(0, first_established_event_arr_index):
                        process_port_info_arr[i].timestamp += during_time

                    process_port_info : ProcessPortInfo = copy.deepcopy(process_port_info_arr[process_port_info_arr.size - 1])
                    process_port_info.timestamp = np.int64(0x0000FFFFFFFFFFFF)
                    process_port_info_arr = np.append(process_port_info_arr, copy.deepcopy(process_port_info))

                    for timestamp, pkt in reader:
                        while timestamp > process_port_info_arr[filter_index + 1].timestamp:
                            filter_index += 1

                        eth = dpkt.ethernet.Ethernet(pkt)

                        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                            ip = eth.data

                            # print(ip.src)
                            # print(int.from_bytes(ip.src), "big")
                            # print(type(ip.src))
                            # print(type(ip.dst))

                            if ip.p == dpkt.ip.IP_PROTO_TCP:
                                if ip.data.sport in process_port_info_arr[filter_index].tcp or ip.data.dport in process_port_info_arr[filter_index].tcp:
                                    writer.writepkt(pkt, timestamp)
                            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                                if ip.data.sport in process_port_info_arr[filter_index].udp or ip.data.dport in process_port_info_arr[filter_index].udp:
                                    writer.writepkt(pkt, timestamp)

                        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                            ip = eth.data

                            if ip.p == dpkt.ip.IP_PROTO_TCP:
                                if ip.data.sport in process_port_info_arr[filter_index].tcp6 or ip.data.dport in process_port_info_arr[filter_index].tcp6:
                                    writer.writepkt(pkt, timestamp)
                            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                                if ip.data.sport in process_port_info_arr[filter_index].udp6 or ip.data.dport in process_port_info_arr[filter_index].udp6:
                                    writer.writepkt(pkt, timestamp)

                # if False:
                #     pass
                
                else:
                    first_val : np.int64 = process_port_info_arr[0].timestamp
                    # for i in range(0, process_port_info_arr.size):
                    #     process_port_info_arr[i].timestamp -= first_val

                    frequency = wintypes.LARGE_INTEGER()
                    ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))

                    for i in range(0, process_port_info_arr.size):
                        process_port_info_arr[i].timestamp = np.float64((process_port_info_arr[i].timestamp) / np.int64(frequency))
                        process_port_info_arr[i].timestamp = process_port_info_arr[i].timestamp

                    process_port_info : ProcessPortInfo = copy.deepcopy(process_port_info_arr[len(process_port_info_arr) - 1])
                    process_port_info.timestamp = np.int64(0x0000FFFFFFFFFFFF)
                    process_port_info_arr = np.append(process_port_info_arr, copy.deepcopy(process_port_info))

                    for i in range(0, process_port_info_arr.size):
                        process_port_info_arr[i].timestamp += 50000

                    for timestamp, pkt in reader:
                        first_timestamp = timestamp
                        break


                    for timestamp, pkt in reader:
                        while timestamp > first_timestamp + process_port_info_arr[filter_index + 1].timestamp:
                            filter_index += 1

                        eth = dpkt.ethernet.Ethernet(pkt)

                        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                            ip = eth.data

                            # print(ip.src)
                            # print(int.from_bytes(ip.src), "big")
                            # print(type(ip.src))
                            # print(type(ip.dst))

                            if ip.p == dpkt.ip.IP_PROTO_TCP:
                                if ip.data.sport in process_port_info_arr[filter_index].tcp or ip.data.dport in process_port_info_arr[filter_index].tcp:
                                    writer.writepkt(pkt, timestamp)
                            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                                if ip.data.sport in process_port_info_arr[filter_index].udp or ip.data.dport in process_port_info_arr[filter_index].udp:
                                    writer.writepkt(pkt, timestamp)

                        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                            ip = eth.data

                            if ip.p == dpkt.ip.IP_PROTO_TCP:
                                if ip.data.sport in process_port_info_arr[filter_index].tcp6 or ip.data.dport in process_port_info_arr[filter_index].tcp6:
                                    writer.writepkt(pkt, timestamp)
                            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                                if ip.data.sport in process_port_info_arr[filter_index].udp6 or ip.data.dport in process_port_info_arr[filter_index].udp6:
                                    writer.writepkt(pkt, timestamp)

                # print(first_val)
                # print(first_timestamp)
                # print(process_port_info_arr[0].timestamp)

                input_pcap_file.close()
                writer_pcap_file.close()

                ctypes.windll.kernel32.DeleteFileW(tmp_file)

                return

def packet_capture(interface_name : str, pcap_file_name : str = "tmp_pcap.pcap", send_pipe = None):
    error_buf = (ctypes.c_char * PCAP_ERRBUF_SIZE)()
    wpcapdll.pcap_open.restype = ctypes.POINTER(pcap_t)
    pcap_device_handle = wpcapdll.pcap_open(interface_name.encode(encode_type), 65536, 0, None, error_buf)
    pcap_file = ctypes.POINTER(pcap_dumper_t)()

    if pcap_device_handle:
        pass
    else:
        print("Unable to open the adapter. {} is not supported by Npcap\n".format(interface_name))
        print(error_buf.value.decode(encode_type))
        raise Exception("Unable to open the adapter. {} is not supported by Npcap\n".format(interface_name))

    wpcapdll.pcap_dump_open.restype = ctypes.POINTER(pcap_dumper_t)
    pcap_file = wpcapdll.pcap_dump_open(pcap_device_handle, pcap_file_name.encode(encode_type))

    callback_func_type = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(pcap_pkthdr), ctypes.POINTER(ctypes.c_ubyte))
    callback_func = callback_func_type(py_packet_handler)

    if send_pipe:
        send_pipe.send("Done")
        if send_pipe.recv() != True:
            raise Exception("invalid recv pipe value")
        send_pipe.close()

    wpcapdll.pcap_loop(pcap_device_handle, 0, callback_func, ctypes.cast(pcap_file, ctypes.POINTER(ctypes.c_ubyte)))

    wpcapdll.pcap_close(pcap_device_handle)


def py_packet_handler(dumpfile : ctypes.POINTER(ctypes.c_ubyte), header : ctypes.POINTER(pcap_pkthdr), pkt_data : ctypes.POINTER(ctypes.c_ubyte)):
    wpcapdll.pcap_dump(dumpfile, header, pkt_data)

# def main():
#         global wpcapdll
#         wpcapdll = ctypes.CDLL(WPCAP_DLL_PATH)

# process_packet_caputre_by_process_name("", "chrome.exe", "", None)