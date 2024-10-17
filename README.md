![image](https://github.com/user-attachments/assets/b048ab83-4413-4f9f-bb58-9908b7c5841f)

# Suricata_ids

CIC-2023이 제공하는 dataset에 맞춰 Network & Applicataion Layer 공격 시나리오를 정했습니다.

https://www.unb.ca/cic/datasets/iotdataset-2023.html


API 이상행위 탐지 룰도 추가하여 최종적인 bunnycode.rules 완성했습니다.


# ids_bunnycode

Python 3.11.9

pip install scapy

pip install tqdm

위의 라이브러리 설치가 필요합니다.

스레드 수는 현재 어느 숫자를 넣든 동일한 속도로 구현됨을 확인했습니다. 이 부분 수정이 필요할 것 같습니다.

진행률을 보여주는게 좋을 것 같아 넣었는데 분석 속도가 빠르면 금방 지나가서 표시되지 않는 것 같습니다.

일단 잘 디코딩했는지 확인하기 위해서 텍스트 파일 형식으로 저장하게 했는데요 경로는 main.py가 실행되는 곳일겁니다.

분석할 파일 경로는 절대경로로 해주시면 돼요(상대경로로는 제가 안해봤습니다)

디코딩 모듈이 잘 만들어지면 텍스트 파일 만드는 부분은 제거를 할 겁니다.

---

목표 : IoT 네트워크 패킷 분석 시스템 개발  
인원 : 4명  
역할 : 팀장(PM) / IoT Deep Dive  
개발일정 : 2024.06.13~2024.08.16  
사용기술 : Suricata, Wireshark, BurpSuite, Vmwear, Nox, Ipcam  
프로젝트 요약 : 실제 기기 IoT 네트워크패킷   
실시간 분석 및 위협 탐지 IDS 개발 , 로그 저장  
Notion : [Team page](https://heavenly-sponge-d64.notion.site/Bunny-code-3aef037d03064dbd8203f8008ec14000)
실행영상 : [youtube1](https://www.youtube.com/watch?v=cajhnAtPMB0&t=1s), [youtube2](https://www.youtube.com/watch?v=Hnw5r-zYygs), [youtube3](https://www.youtube.com/watch?v=TrMiYTCxhuE)  
기획안 : [Google Drive](https://drive.google.com/file/d/19mj3-EDCOLqJ2pD5kfY_OSwfh8t4DmJV/view),  [Google Drive2](https://drive.google.com/file/d/1q25tTZvHWgv_Y-Ysz5jcpdYpq0SAiVzP/view)  
+ 기획안은 프로젝트의 주제가 2번 변경되어 조금 다를수 있습니다.  
+ ㄴ 구름 & 카카오 프로젝트 진행 중 관리자의 전달 실수로 인하여 변경됨.  
발표자료 : [Google Drive](https://drive.google.com/file/d/1Lzg4cSfM-lOgUni9AhSGEI7BzxtjDtQc/view)  
개인기록 : [Notion Link](https://heavenly-sponge-d64.notion.site/7fd7f55381d94c9e9e091c83fb029b71)

주요 기능 :  
침입 탐지 시스템 (IDS) 다양한 공격 시도를 감지하고, 이를 경고하는 기능을 구현  
IoT-23 및 CIC IoT 23  데이터셋을 사용 네트워크 트래픽의 정상 동작과 비정상 동작을 구분  
실제 ipcam IoT 트래픽 탐지 기능  
로그 수집 및 파싱 기능  
Suricata 기반 룰 적용  
GitHub 통합: 프로젝트 코드는 GitHub에 공개를 통해 커뮤니티의 기여  

개인 성과:  
환경구성 및 테스트   
Suricata 탐지 룰 제작 및   
IoT web/mobile 패킷 캡처  
실기기 Ipcam 분석 및 패킷 탐지 및 경고  
문서 작성 및 발표  
노션 팀 페이지 제작  



