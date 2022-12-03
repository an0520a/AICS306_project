WINAPI 사용 목록
===============

## (작업관리자 프로세스의) 권한상승(set_privilege)
>* OpenProcessToken [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
>* GetCurrentProcess [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess)
>* LookupPrivilegeValue [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea)
>* AdjustTokenPrivileges [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
>* GetLastError [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
>* CloseHandle [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/handleapi/nf-handleapi-closehandle)

## 프로세스 리스트 (get_process_info_list)
>### 프로세스 목록
>   >* CreateToolhelp32Snapshot [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
>   >* Process32First [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)
>   >* Process32Next [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)
>   >* CloseHandle [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/handleapi/nf-handleapi-closehandle)
>### 프로세스 세부 정보
>   >* OpenProcess [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
>   >#### 프로세스 소유자, 소유자의 도메인, 소유자의 타입
>   >   >* LookupAccountSid [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/winbase/nf-winbase-lookupaccountsida)
>   >   >* OpenProcessToken [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
>   >   >* GetTokenInformation [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
>   >#### 프로세스 메모리 정보
>   >   >* GetProcessMemoryInfo [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
>   >#### 프로세스 cpu time 정보
>   >   >* GetProcessTimes [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
>   >#### 프로세스 정보 측정 시간
>   >   >* QueryPerformanceCounter [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)

## 시스템 메모리 정보
>* GetPhysicallyInstalledSystemMemory [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory)
>* GetPerformanceInfo [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/psapi/nf-psapi-getperformanceinfo)
>* GlobalMemoryStatusEx [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex)

## CPU 사용률 관련 정보 get
>* GetSystemInfo [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)
>* QueryPerformanceFrequency [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency)

## 프로세스 kill
>* OpenProcess [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
>* TerminateProcess [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
>* CloseHandle [(MSDN)](https://learn.microsoft.com/ko-kr/windows/win32/api/handleapi/nf-handleapi-closehandle)