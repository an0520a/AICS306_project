# PCPN(Packet Capture Filtering By Process Name)

Introduction
------------
PCPN은 강력한 GUI 프로세스 패킷 캡처 툴입니다.  
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

[npcap](https://npcap.com/)과 WinDivert(https://reqrypt.org/windivert.html)를 사용하여 만들어졌으며, GPL 라이센스가 적용되었습니다.  

<br>
<br>

How to use
----------
PCPN은 관리자 권한으로 요구합니다.  
일반 사용자 권한으로 실행시 에러를 발생시키고 프로그램을 종료합니다.  
<img src="document\img\READEME_img_1.png" width="30%">
<br><br>
정상적으로 실행되었다면 인터페이스를 고르는 창이 나타납니다.  
인터페이스를 고르고 선택 버튼을 눌러, 패킷을 캡처할 인터페이스를 선택할 수 있습니다
<img src="document\img\READEME_img_2.png" width="50%">
 
마지막으로 다음과 같은 화면을 만날 수 있습니다.  
해당 화면에서는 주기적으로 각종 프로세스에 대한 정보가 갱신됩니다.  
해당 화면에서 캡처할 프로세스를 선택하고 Capture Start 버튼을 눌러 해당 
프로세스 (또는 그와 동일한 이름을 가진)의 패킷 캡처를 진행할 수 있습니다.
캡처한 패킷은 pcap 파일의 형식으로 저장되며, 
패킷 캡처를 중지하고, 저장하
<img src="document\img\READEME_img_3.png" width="70%">
<br><br>