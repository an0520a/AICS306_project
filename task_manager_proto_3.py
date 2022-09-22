import wmi

process_list = wmi.WMI().Win32_Process()

print("%-27.25s %-5s" % ("name", "pid"))
print("-" * 32)
for proc in process_list:
    result = proc.GetOwner()
    print("%-27.25s %-5d %8.8s" % (proc.Name, proc.ProcessId, result[2]))