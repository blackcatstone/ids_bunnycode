from scapy.all import *
import os

# 기존 PCAP 파일 경로와 새로운 파일 경로
original_pcap = 'C:/Users/whdwns/Desktop/web test1.pcap'

# 기존 PCAP 파일 읽기
packets = rdpcap(original_pcap)

# 기존 패킷 정보
src_mac = "50:eb:f6:b6:9d:95"
dst_mac = "00:07:70:f7:2e:ae"
src_ip = "175.210.7.224"
dst_ip = "162.159.134.234"
src_port = 61326
dst_port = 443
seq_num = 55
ack_num = 1011

# 패킷 생성 함수 (TCP 핸드셰이크 시뮬레이션)
def create_syn_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, flags="S")
    packet = ether / ip / tcp
    return packet

def create_syn_ack_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, ack=ack_num, flags="SA")
    packet = ether / ip / tcp
    return packet

def create_ack_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, ack=ack_num, flags="A")
    packet = ether / ip / tcp
    return packet


# TCP 패킷 생성 및 추가
num_tcp_packets = 1000  # 생성할 TCP 패킷의 수
for i in range(num_tcp_packets):
    syn_packet = create_syn_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num + i)
    syn_ack_packet = create_syn_ack_packet(dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port, ack_num, seq_num + i + 1)
    ack_packet = create_ack_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq_num + i + 1, ack_num + 1)
    packets.append(syn_packet)
    packets.append(syn_ack_packet)
    packets.append(ack_packet)
    time.sleep(0.01)  # 패킷 전송 간격을 10ms로 설정

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/pcap DDOS2.pcap'
wrpcap(output_pcap, packets)

print(f"DDoS 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")