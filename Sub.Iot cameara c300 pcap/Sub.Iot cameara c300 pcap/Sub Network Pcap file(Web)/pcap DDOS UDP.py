from scapy.all import *
import os

# 기존 PCAP 파일 경로와 새로운 파일 경로
original_pcap = 'C:/Users/whdwns/Desktop/pcap DDOS.pcap'

# 기존 PCAP 파일 읽기
packets = rdpcap(original_pcap)

# 기존 패킷 정보
src_mac = "e4:5f:01:55:90:c4"
dst_mac = "9c:8e:cd:1d:ab:9f"
src_ip = "192.168.137.36"
dst_ip = "192.168.137.49"
src_port = 57210
dst_port = 19659
data_payload = bytes.fromhex("00000000000001b9")

# 패킷 생성 함수
def create_ddos_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    data = Raw(load=payload)
    packet = ether / ip / udp / data
    return packet

# DDoS 패킷 생성 및 추가
num_ddos_packets = 1000  # 생성할 DDoS 패킷의 수
for _ in range(num_ddos_packets):
    ddos_packet = create_ddos_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, data_payload)
    packets.append(ddos_packet)

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/pcap DDOS1.pcap'
wrpcap(output_pcap, packets)

print(f"DDoS 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")