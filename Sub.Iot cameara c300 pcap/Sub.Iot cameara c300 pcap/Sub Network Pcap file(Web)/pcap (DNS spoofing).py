from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR

# 기존 패킷 정보
src_mac = "50:eb:f6:b6:9d:95"
dst_mac = "00:07:70:f7:2e:ae"
src_ip = "192.168.0.100"
dst_ip = "8.8.8.8"
src_port = 33333
dst_port = 53

# 스푸핑 대상 도메인과 IP
target_domain = "example.com"
spoofed_ip = "123.123.123.123"

# 패킷 생성 함수
def create_dns_spoof_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, target_domain, spoofed_ip):
    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    dns = DNS(
        id=0xAAAA,  # DNS transaction ID
        qr=1,       # This is a response
        aa=1,       # Authoritative Answer
        qdcount=1,  # Number of questions
        ancount=1,  # Number of answers
        qd=DNSQR(qname=target_domain),
        an=DNSRR(rrname=target_domain, ttl=10, rdata=spoofed_ip)
    )
    packet = ether / ip / udp / dns
    return packet

# 기존 PCAP 파일 읽기
original_pcap = 'C:/Users/whdwns/Desktop/web test.pcap'  # 파일 경로 수정
packets = rdpcap(original_pcap)

# DNS 스푸핑 패킷 생성 및 추가
num_dns_packets = 10  # 생성할 DNS 스푸핑 패킷의 수
for i in range(num_dns_packets):
    dns_spoof_packet = create_dns_spoof_packet(src_mac, dst_mac, src_ip, dst_ip, src_port + i, dst_port, target_domain, spoofed_ip)
    packets.append(dns_spoof_packet)
    time.sleep(0.01)  # 패킷 전송 간격을 10ms로 설정

# 새로운 PCAP 파일로 저장
output_pcap = 'C:/Users/whdwns/Desktop/output_with_dns_spoofing.pcap'  # 파일 경로 수정
wrpcap(output_pcap, packets)

print(f"DNS 스푸핑 패킷이 추가된 새로운 PCAP 파일이 '{output_pcap}'에 저장되었습니다.")
