from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse

# 기존 패킷 정보
src_mac = "50:eb:f6:b6:9d:95"
dst_mac = "00:07:70:f7:2e:ae"
src_ip = "175.210.7.224"
dst_ip = "162.159.134.234"
src_port_start = 50000  # 시작 소스 포트
dst_port = 80  # HTTP 포트
seq_num = 55

# 로그인 시도에 사용할 아이디와 비밀번호 목록
usernames = ["admin", "user", "test"]
passwords = ["password", "123456", "admin"]

# 패킷 생성 함수
def create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num, username, password):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, flags="PA")
    http_req = HTTPRequest(
        Method=b"POST",
        Path=b"/login",
        Http_Version=b"HTTP/1.1",
        Host=b"example.com",
        User_Agent=b"Scapy Brute Force",
        Connection=b"keep-alive",
        Content_Type=b"application/x-www-form-urlencoded",
        Content_Length=b"29"
    )
    post_data = f"username={username}&password={password}".encode()
    packet = ether / ip / tcp / http_req / post_data
    return packet

# 기존 PCAP 파일 읽기
original_pcap = 'C:/Users/whdwns/Desktop/web test.pcap'  # 파일 경로 수정
packets = rdpcap(original_pcap)

# Dictionary Brute Force 패킷 생성 및 추가
seq_increment = 1
for username in usernames:
    for password in passwords:
        src_port = src_port_start + seq_increment  # 각 패킷마다 소스 포트 변경
        http_packet = create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num + seq_increment, username, password)
        packets.append(http_packet)
        seq_increment += 1
        time.sleep(0.01)  # 패킷 전송 간격을 10ms로 설정

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/bruteforce.pcap'  # 파일 경로 수정
wrpcap(output_pcap, packets)

print(f"Dictionary Brute Force 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")
