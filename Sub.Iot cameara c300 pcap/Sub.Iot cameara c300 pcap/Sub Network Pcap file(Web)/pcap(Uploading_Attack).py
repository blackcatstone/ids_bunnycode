from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse

# 기존 패킷 정보
src_mac = "dc:a6:32:c9:e6:f4"
dst_mac = "dc:a6:32:dc:27:d5"
src_ip = "192.168.137.13"
dst_ip = "192.168.137.147"
src_port_start = 50000  # 시작 소스 포트
dst_port = 80  # HTTP 포트
seq_num = 3221456082
ack_num = 797427787

# 악성 파일 데이터 (간단한 예제로 텍스트 파일 데이터)
file_content = "This is a malicious file content."

# 패킷 생성 함수
def create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, file_content):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, ack=ack_num, flags="PA")
    http_req = HTTPRequest(
        Method=b"POST",
        Path=b"/upload",
        Http_Version=b"HTTP/1.1",
        Host=b"192.168.137.13",
        User_Agent=b"Scapy Uploading Attack",
        Connection=b"keep-alive",
        Content_Type=b"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        Content_Length=b"500"
    )
    post_data = (
        "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"malicious.txt\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
        f"{file_content}\r\n"
        "------WebKitFormBoundary7MA4YWxkTrZu0gW--"
    ).encode()
    packet = ether / ip / tcp / http_req / post_data
    return packet

# 기존 PCAP 파일 읽기
original_pcap = 'C:/Users/whdwns/Desktop/web test.pcap'  # 파일 경로 수정
packets = rdpcap(original_pcap)

# Uploading Attack 패킷 생성 및 추가
num_upload_packets = 10  # 생성할 Uploading Attack 패킷의 수
for i in range(num_upload_packets):
    src_port = src_port_start + i  # 각 패킷마다 소스 포트 변경
    upload_packet = create_http_post_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num + i, ack_num, file_content)
    packets.append(upload_packet)
    time.sleep(0.01)  # 패킷 전송 간격을 10ms로 설정

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/output_with_uploading_attack.pcap'  # 파일 경로 수정
wrpcap(output_pcap, packets)

print(f"Uploading Attack 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")
