from scapy.all import *

# 기존 PCAP 파일 경로와 새 파일 경로 설정
pcap_file = "C:/Users/whdwns/Desktop/web test.pcap"
new_pcap_file = "C:/Users/whdwns/Desktop/td.pcap"

# 기존 PCAP 파일 읽기
try:
    packets = rdpcap(pcap_file)
except FileNotFoundError:
    print(f"파일을 찾을 수 없습니다: {pcap_file}")
    exit(1)

# 비정상 패킷 생성 (이더넷 프레임 포함)
ether = Ether()
ip = IP(src="192.168.1.100", dst="192.168.1.101")
tcp = TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=1001)
payload = "GET /search.php?query=' OR '1'='1 HTTP/1.1\r\nHost: victim.com\r\n\r\n"
malicious_packet = ether / ip / tcp / payload

# 비정상 패킷을 기존 패킷 리스트에 추가
packets.append(malicious_packet)

# 수정된 패킷 리스트를 새로운 PCAP 파일로 저장
wrpcap(new_pcap_file, packets)

print(f"비정상 패킷이 추가된 새로운 PCAP 파일이 '{new_pcap_file}'로 저장되었습니다.")
