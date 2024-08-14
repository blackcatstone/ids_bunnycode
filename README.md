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
