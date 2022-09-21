import wmi

wmi_obj = wmi.WMI()
process_list = wmi_obj.Win32_process()

for process in process_list:
    print(process.ProcessId, process.Name)