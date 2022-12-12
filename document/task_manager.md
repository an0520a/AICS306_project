ProcessInfo 데이터 클래스
=============

구문
----
```python
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
    process_memory_info : PROCESS_MEMORY_COUNTERS = PROCESS_MEMORY_COUNTERS()
    measurement_time : wintypes.LARGE_INTEGER = wintypes.LARGE_INTEGER()
    token_flag : bool = False
```

<br>

멤버
----
```process_pid```  
프로세스를 식별하는 pid 입니다.
<br><br>
```process_name```  
프로세스의 이름입니다.
<br><br>
```process_path```  
프로세스의 경로입니다.
<br><br>
```process_owner```  
프로세스의 사용자 이름입니다.
<br><br>
```process_owner_domain```  
프로세스 sid 검색에서 발견된 첫 번째 도메인 이름입니다.
<br><br>
```process_owner_type```  
프로세스 sid가 있는 계정 유형입니다.
<br><br>
```process_time_info_dict```  
프로세스 시간 정보에 관한 딕셔너리입니다.
<br><br>
```process_memory_info```  
프로세스 메모리 정보에 관한 딕셔너리입니다.
<br><br>
```measurement_time```  
해당 정보가 측정된 시간입니다.
<br><br>
```token_flag```  
프로세스의 사용자 이름, 프로세스 계정 유형 등의 정보가 정상적으로 획득 되었는지 나타냅니다.
True 라면 정상 획득을, False라면 비정상 획득을 의미합니다.

<br>

설명
----
프로세스에 관한 정보를 저장하는데 사용됩니다.

<br>
<br>
<br>





PreprocessedProcessInfo 데이터 클래스
=============

구문
----
```python
class PreprocessedProcessInfo(ProcessInfo):
    process_memory_usage: float = 0  # 단위 : KB
    process_cpu_usage_rate: float = 0
    process_memory_usage_rate: float = 0
```

<br>

멤버
----
```process_pid```  
프로세스를 식별하는 pid 입니다.
<br><br>
```process_name```  
프로세스의 이름입니다.
<br><br>
```process_path```  
프로세스의 경로입니다.
<br><br>
```process_owner```  
프로세스의 사용자 이름입니다.
<br><br>
```process_owner_domain```  
프로세스 sid 검색에서 발견된 첫 번째 도메인 이름입니다.
<br><br>
```process_owner_type```  
프로세스 sid가 있는 계정 유형입니다.
<br><br>
```process_time_info_dict```  
프로세스 시간 정보에 관한 딕셔너리입니다.
<br><br>
```process_memory_info```  
프로세스 메모리 정보에 관한 딕셔너리입니다.
<br><br>
```measurement_time```  
해당 정보가 측정된 시간입니다.
<br><br>
```token_flag```  
프로세스의 사용자 이름, 프로세스 계정 유형 등의 정보가 정상적으로 획득 되었는지 나타냅니다.
True 라면 정상 획득을, False라면 비정상 획득을 의미합니다.
<br><br>
```process_memory_usage```  
프로세스의 메모리 사용량(workingset의 크기) 입니다. KB 단위입니다.
<br><br>
```process_cpu_usage_rate```  
프로세스의 cpu 사용률 입니다.
<br><br>
```process_memory_usage_rate```  
프로세스의 메모리 사용률 입니다.

<br>

설명
----
프로세스에 관한 정보 전처리 한 후 저장하는데 사용됩니다.
ProcessInfo 데이터 클래스를 상속 받습니다.

<br>
<br>
<br>





HardSystemMemoryInfo 데이터 클래스
=============

구문
----
```python
@dataclass
class HardSystemMemoryInfo:
    kInstall: int = None
    kHardwareReserved: int = None
    kTotal: int = None
```

<br>

멤버
----
```kInstall```  
설치된 메모리의 총 크기입니다.  
Byte 단위입니다.
<br><br>
```kHardwareReserved```  
하드웨어에 예약된 메모리의 총 크기입니다.  
Byte 단위입니다.
<br><br>
```kTotal```  
실제 사용할 수 있는 메모리의 총 크기(설치 된 메모리의 총 크기 - 하드웨어에 예약된 메모리의 총크기) 입니다.  
Byte 단위입니다.  

<br>

설명
----
하드웨어를 변경하지 않는 한 변경되지 않는 메모리 정보를 나타냅니다.

<br>
<br>
<br>





SoftSystemMemoryInfo 데이터 클래스
=============

구문
----
```python
@dataclass
class SoftSystemMemoryInfo:
    available: int = None
```

<br>

멤버
----
```available```  
사용할 수 있는 메모리의 양 (캐시에 사용되는 메모리(대기) + 여유 메모리)를 나타냅니다.
Byte 단위입니다.

<br>

설명
----
지속적으로 변동되는 메모리 정보를 나타냅니다.

<br>
<br>
<br>

SystemMemoryInfo 데이터 클래스
=============

구문
----
```python
@dataclass
class SystemMemoryInfo:
    hard_system_memory_info: HardSystemMemoryInfo = field(default_factory=dataclass)
    soft_system_memory_info: SoftSystemMemoryInfo = field(default_factory=dataclass)
```

<br>

멤버
----
```hard_system_memory_info```  
하드웨어를 변경하지 않는 한 변경되지 않는 메모리 정보를 나타냅니다.
<br><br>
```soft_system_memory_info```  
지속적으로 변경되는 않는 메모리 정보를 나타냅니다.

<br>

설명
----
시스템 메모리에 대한 정보를 나타냅니다.

<br>
<br>
<br>





InterfaceInfo 데이터 클래스
=============

구문
----
```python
@dataclass(order = True)
class InterfaceInfo:
    name : str = ""
    description : str = ""
```

<br>

멤버
----
```name```  
인터페이스의 이름입니다.
<br><br>
```description```  
인터페이스에 대한 설명입니다.

<br>

설명
----
네트워크 인터페이스 정보에 대한 데이터 클래스로, 네트워크 인터페이스의 이름과 그에 대한 설명을 포함합니다.  
다음 예제의 인터페이스 정보가 있다고 합시다.  
```\Device\NPF_{4E273621-5161-46C8-895A-48D0E52A0B83} (Realtek RTL8029(AS) Ethernet Adapter)```  
이는 InterfaceInfo 데이터 클래스에 다음 형태로 저장됩니다.  
```name = \Device\NPF_{4E273621-5161-46C8-895A-48D0E52A0B83}, description = Realtek RTL8029(AS) Ethernet Adapter```

<br>
<br>
<br>

kill_process 함수
===========================

구문
----
```python
def kill_process(
    [in] process_pid : int
) -> None
```

<br>

매개변수
-------
```[in] process_pid```  
프로세스를 식별하는 pid입니다.

<br>

반환 값
-------
없습니다.

<br>

설명
----
해당 pid가 식별하는 프로세스를 죽입니다.  
만약 권한이 부족한 프로세스를 죽일려 할 경우, 예외가 발생합니다.  
현재 gui 프로그램에서는 프로그램이 종료됩니다.

<br>
<br>
<br>





set_privilege 함수
===========================

구문
----
```python
def set_privilege(
    [in] szPrivilege: str
) -> bool
```

<br>

매개변수
-------
```[in] szPrivilege```  
권한 상수입니다. 권한 상수 목록은 [다음](https://learn.microsoft.com/ko-kr/windows/win32/secauthz/privilege-constants)을 참고하십시오

<br>

반환 값
-------
성공하면 True를, 실패하면 False를 반환합니다.

<br>

설명
----
현재 프로세스의 권한을 매개변수로 받은 권한상수가 의미 하는 권한으로 바꿉니다.

<br>
<br>
<br>





get_process_info_list 함수
===========================

구문
----
```python
def get_process_info_list() -> list[ProcessInfo]
```

<br>

매개변수
-------
없습니다.

<br>

반환 값
-------
list[ProcessInfo] 입니다.  
프로세스의 목록과 그에 대한 정보를 나타냅니다.

<br>

설명
----
현재 존재하는 프로세스의 목록과 그에 대한 정보를 얻어옵니다.

<br>
<br>
<br>





get_hard_system_memory_info 함수
===========================

구문
----
```python
def get_hard_system_memory_info() -> HardSystemMemoryInfo
```

<br>

매개변수
-------
없습니다.

<br>

반환 값
-------
```HardSystemMemoryInfo``` 구조체 입니다.

<br>

설명
----
하드웨어를 변경하지 않는 한 변동되지 않는 시스템 메모리 정보에 대해 얻어옵니다.

<br>
<br>
<br>





get_soft_system_memory_info 함수
===========================

구문
----
```python
def get_soft_system_memory_info() -> SoftSystemMemoryInfo
```

<br>

매개변수
-------
없습니다.

<br>

반환 값
-------
```SoftSystemMemoryInfo``` 구조체 입니다.

<br>

설명
----
지속적으로 변동되는 시스템 메모리 정보에 대해 얻어옵니다.

<br>
<br>
<br>





get_system_memory_info 함수
===========================

구문
----
```python
def get_system_memory_info() -> SystemMemoryInfo
```

<br>

매개변수
-------
없습니다.

<br>

반환 값
-------
```SystemMemoryInfo``` 구조체 입니다.

<br>

설명
----
시스템 메모리 정보에 대해 얻어옵니다.

<br>
<br>
<br>





get_interface_info_list 함수
===========================

구문
----
```python
def get_interface_info_list() -> list[InterfaceInfo]
```

<br>

매개변수
-------
없습니다.

<br>

반환 값
-------
반환 값은 InterFaceInfo의 리스트입니다.  
InterfaceInfo의 순서는 실행 때 마다 달라 질 수도 있습니다. 

<br>

설명
----
존재하는 네트워크 인터페이스를 얻어옵니다.

<br>
<br>
<br>





preprocessing_process_info 함수
===========================

구문
----
```python
def preprocessing_process_info(
    [in] prev_process_info_list: list[ProcessInfo], 
    [in] process_info_list: list[ProcessInfo]
) -> list[PreprocessedProcessInfo]:
```

<br>

매개변수
-------
```[in] prev_process_info_list```  
이전 ProcessInfo의 list 입니다.  
다양한 시간대의 이전 ProcessInfo의 list를 넣어도, 자동으로 처리됩니다.
<br><br>
```[in] process_info_list```  
현재 ProcessInfo의 list 입니다.

<br>

반환 값
-------
```list[preprocessed_process_info_list]``` 입니다.

<br>

설명
----
프로세스의 cpu 사용률, 프로세스의 메모리 사용량, 프로세스의 메모리 사용률 등을 계산하여 이를 PreprocessedProcessInfo 데이터 클래스에 담아 리스트의 형태로 반환합니다.  
만약 prev_process_info_list에만 존재하고 process_info_list에는 존재하지 않는 프로세스가 있다면(= 현 시점에서는 죽어버린 프로세스가 있다면), 결과에 포함되지 않습니다.  
만약 prev_process_info_list에만 존재하지 않고 process_info_list에는 존재하는 프로세스가 있다면(= 현 시점에서 새로 생긴 프로세스가 있다면), 결과에 포함하되 cpu 사용률은 계산하지 않고 0으로 채웁니다.

<br>
<br>
<br>





start_process_packet_caputre_by_process_name 함수
================================================

구문
----
```python
def start_process_packet_caputre_by_process_name(
    [in] interface_name : str, 
    [in] process_name : str, 
    [in] pcap_name : str
) -> tuple(multiprocessing.Process, multiprocessing.connection.Pipe)
```

<br>

매개변수
-------
```[in] interface_name```  
패킷을 캡처하고자 하는 네트워크 인터페이스의 이름 입니다.
<br><br>
```[in] process_name```  
패킷을 캡처하고자 하는 프로세스의 이름입니다.  
경로를 포함하지 않습니다.
<br><br>
```[in] pcap_name```  
캡처한 패킷을 저장할 pcap 파일 이름입니다.

<br>

반환값
------
multiprocessing.Process와 multiprocessing.connection.Pipe의 튜플입니다.

<br>

설명
----
프로세스의 이름이 process_name인 프로세스의 송수신 패킷을 캡처합니다.  
process_packet_caputre_by_process_name 함수를 taskmanager packet manager라는 이름의 subprocess로 생성하고 시작하게 됩니다. subprocess는 반환 받은 튜플을 매개변수로 join_process_packet_caputre_by_process_name 함수를 호출 할 때 까지 지속적으로 패킷을 캡처하게 됩니다. 정상적인 작동을 위해서, 반환받은 튜플 값을 변경하거나 join_process_packet_caputre_by_process_name의 매개변수 외로 사용해서는 안됩니다.

<br>
<br>
<br>





join_process_packet_caputre_by_process_name 함수
================================================

구문
----
```python
def start_process_packet_caputre_by_process_name(
    [in] process_pipe_tuple : tuple(multiprocessing.Process, multiprocessing.connection.Pipe)
) -> tuple(multiprocessing.Process, multiprocessing.connection.Pipe)
```

<br>

매개변수
-------
```[in] process_pipe_tuple```  
start_process_packet_caputre_by_process_name의 반환값 ```tuple(multiprocessing.Process, multiprocessing.connection.Pipe)```입니다. 

<br>

반환값
------
없습니다.

<br>

설명
----
start_process_packet_caputre_by_process_name 함수로 시작한 특정 이름을 가진 프로세스의 패킷 캡처를 중지하고, 지금까지 캡처한 패킷을 pcap 파일로 저장합니다.  
start_process_packet_caputre_by_process_name 함수를 통해 생성한 subprocess에 매개변수로 입력받은 튜플의 파이프를 이용하여 signal.SIGINT를 send를 하게 되고, subprocess가 recv 파이프를 통해 이를 받으면 패킷캡처를 중지하고 패킷 필터링 및 저장 과정으로 넘어가게 됩니다.
패킷 필터링 및 저장 과정에서 dpkt 모듈을 호출하게 되는데, 이 부분은 C 라이브러리 함수를 사용하지 않고 python native 코드여서 상당한 처리 시간이 필요하게 됩니다.
이러한 처리가 완료될 때 까지 main프로세스는 일시적으로 sleep 상태가 됩니다.

<br>
<br>
<br>





global_init 함수
================================================

구문
----
```python
def global_init() -> None
```

<br>

매개변수
-------
없습니다.

<br>

반환값
------
없습니다.

<br>

설명
----
여러가지 전역 변수의 초기화를 시행합니다.  

<br>
<br>
<br>





dependency_check 함수
================================================

구문
----
```python
def dependency_check() -> None
```

<br>

매개변수
-------
없습니다.

<br>

반환값
------
없습니다.

<br>

설명
----
필수 dll 존재여부 등 프로그램 실행에 필요한 여러가지 확인을 수행합니다.  
만약 dll이 존재하지 않아 프로그램 실행에 지장이 있다면 예외를 발생시킵니다.

<br>
<br>
<br>
