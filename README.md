# PCPN(Packet Capture Filtering By Process Name)

Introduction
------------
PCPN is a powerful GUI process tcp/udp packet capture tool that supports capturing packets from a specific process based on its name and process ID (TBD). It can be used on Windows 10 64-bit or higher. 

PCPN supports the following features:
- Packet capture of a process with a specific name
- Packet capture of a process with a specific PID (TBD)
- Process list and information
    - Process name
    - Process owner
    - Process PID
    - Process CPU usage
    - Process memory usage
    - Process memory usage rate
- Process kill

PCPN was created using [npcap](https://npcap.com/) and [WinDivert](https://reqrypt.org/windivert.html) and is licensed under the GPL license.

How to use
----------
PCPN requires administrator privileges. If run with normal user privileges, an error will occur and the program will exit. 

If it runs correctly, a window will appear asking you to choose an interface. Select the interface and press the select button to choose the interface to capture packets from.

<img src="document\img\READEME_img_2.png" width="50%">

Finally, you will see a screen where information about various processes is periodically updated. If information such as memory usage rate cannot be obtained for a specific process, CPU usage/memory usage/memory usage rate will be displayed as 0. If necessary, you can sort each column in ascending order by selecting the top of each column. 

Select the process you want to capture on the screen and press the Capture Start button to start capturing packets from the process (or one with the same name). If you want to stop capturing packets, you can do so by pressing the Capture Stop button. The captured packets are saved in pcap file format, and you can specify the path and name using the Save Path. 

You can also use the kill button to end the selected process.

<img src="document\img\READEME_img_3.png" width="70%">

Warning
---------
1. IPv6 packets cannot be captured. (I did not have an environment to test with IPv6 and could not debug it.)
2. It is not guaranteed that all traffic will be captured accurately, and any problems arising from this are the responsibility of the user.


<br><br><br><br><br>
# PCPN(Packet Capture Filtering By Process Name)

Introduction
------------
PCPN은 강력한 GUI 프로세스 tcp/udp 패킷 캡처 툴입니다.  
프로세스 이름과 프로세스 ID(예정)을 통하여 특정 프로세스의 패킷 캡처를 지원합니다.  
64비트 Windows 10 이나 그 이상 버전의 윈도우에서 사용할 수 있습니다.  
<br>
PCPN은 다음 기능을 지원합니다.  
- 특정 이름을 사용하는 프로세스의 패킷 캡처
- 특정 pid를 사용하는 프로세스의 패킷 캡처 (예정)
- 프로세스 목록 및 정보 확인
    - 프로세스 이름
    - 프로세스의 소유자
    - 프로세스 pid
    - 프로세스의 cpu 사용률
    - 프로세스의 메모리 사용량 확인
    - 프로세스 메모리 사용률 확인
- 프로세스 킬

[npcap](https://npcap.com/)과 [WinDivert](https://reqrypt.org/windivert.html)를 사용하여 만들어졌으며, GPL 라이센스가 적용되었습니다.  

<br>
<br>

How to use
----------
PCPN은 관리자 권한으로 요구합니다.  
일반 사용자 권한으로 실행시 에러를 발생시키고 프로그램을 종료합니다.

<img src="document\img\READEME_img_1.png" width="30%">

<br><br>
정상적으로 실행되었다면 인터페이스를 고르는 창이 나타납니다.  
인터페이스를 고르고 선택 버튼을 눌러, 패킷을 캡처할 인터페이스를 선택할 수 있습니다.

<img src="document\img\READEME_img_2.png" width="50%">

<br><br>
마지막으로 다음과 같은 화면을 만날 수 있습니다.  
해당 화면에서는 주기적으로 각종 프로세스에 대한 정보가 갱신됩니다. 
이때 만약 특정 프로세스에 대한 메모리 사용률 등의 정보를 얻는데 실패한다면, CPU 사용률 / 메모리 사용량 / 메모리 사용률은 0으로 표시됩니다.  
필요하다면, 각 열의 맨 위를 선택하여 오름차순으로 정렬을 할 수 있습니다.  
해당 화면에서 캡처할 프로세스를 선택하고 Capture Start 버튼을 눌러 해당 
프로세스 (또는 그와 동일한 이름을 가진)의 패킷 캡처를 진행할 수 있습니다.
패킷 캡처를 중지하길 원한다면 Capture Stop 버튼을 통해 중지할 수 있습니다.
캡처한 패킷은 pcap 파일의 형식으로 저장되며, Save Path를 통해 경로와 이름을 지정할 수 있습니다.  
또한 프로세스를 선택한 후 kill 버튼을 통하여 해당 프로세스를 종료할 수 있습니다.  

<img src="document\img\READEME_img_3.png" width="70%">

<br><br>

Warning
---------
1. IPv6 패킷은 캡처할 수 없습니다. (IPv6에서 테스트할 수 있는 환경이 없었고, 결국 디버깅을 하지 못했습니다.)
2. 모든 트래픽이 정확하게 캡처될 수 있다고 보장할 수 없고, 이로 인해 발생한 문제는 사용자에게 있습니다.
<br><br>
