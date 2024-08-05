from pcap_decoder import ParallelPCAPReader, Packet
from network_stream import StreamAnalyzer
from typing import Dict, List, Any
from collections import defaultdict
import json

class HeaderExtractor:
    def __init__(self):
        self.stream_analyzer = StreamAnalyzer()
        self.benign_packets = []
        self.malicious_packets = []
        self.ip_counter = defaultdict(int)
        self.syn_counter = defaultdict(int)
        self.icmp_counter = defaultdict(int)
        self.tcp_counter = defaultdict(int)
        self.udp_counter = defaultdict(int)

    def process_packet(self, packet: Packet):
        packet_info = packet.to_dict()
        self.stream_analyzer.process_packet(packet_info)
        
        if self.is_malicious(packet_info):
            self.malicious_packets.append(packet_info)
        else:
            self.benign_packets.append(packet_info)

    def is_malicious(self, packet_info: Dict[str, Any]) -> bool:
        is_malicious = False
        reasons = []

        protocol_stack = packet_info['protocol_stack']
        
        #아래의 이유에 해당하는건 언제나 '가능성'이 존재함을 뜻함
        # 1. IP Spoofing
        if 'IP' in protocol_stack:
            src_ip = protocol_stack['IP']['src']
            self.ip_counter[src_ip] += 1
            if self.ip_counter[src_ip] > 1000:  # 임의의 임계값
                is_malicious = True
                reasons.append("IP Spoofing") #High number of packets from same source IP

        # 2. SYN Flooding
        if 'TCP' in protocol_stack and 'S' in protocol_stack['TCP']['flags']:
            dst_ip = protocol_stack['IP']['dst']
            self.syn_counter[dst_ip] += 1
            if self.syn_counter[dst_ip] > 100:  # 임의의 임계값
                is_malicious = True
                reasons.append("SYN Flooding") #High number of SYN packets to same destination

        # 3. ICMP Flooding
        if 'ICMP' in protocol_stack:
            src_ip = protocol_stack['IP']['src']
            self.icmp_counter[src_ip] += 1
            if self.icmp_counter[src_ip] > 50:  # 임의의 임계값
                is_malicious = True
                reasons.append("ICMP Flooding") #High number of ICMP packets from same source

        # 4. Abnormal Packet Size
        if packet_info['length'] > 1500 or packet_info['length'] < 20:
            is_malicious = True
            if packet_info['length'] > 1500:
                reasons.append("Abnormal Packet Size") #Packet size exceeds typical MTU, indicating possible fragmentation or non-standard configuration
            else:
                reasons.append("Abnormal Packet Size") #Packet size is unusually small, possibly indicating malformed or suspicious packet content

        # 5. Abnormal TTL Value
        if 'IP' in protocol_stack:
            ttl = protocol_stack['IP']['ttl']
            if ttl < 10:
                is_malicious = True
                reasons.append("Abnormal TTL Value") #TTL too low, possible spoofed or misrouted packet

        # 6. DDoS TCP
        if 'TCP' in protocol_stack:
            dst_ip = protocol_stack['IP']['dst']
            self.tcp_counter[dst_ip] += 1
            if self.tcp_counter[dst_ip] > 1000:  # 임의의 임계값
                is_malicious = True
                reasons.append("DDoS TCP") #High number of TCP packets to same destination

        # 7. DDoS UDP
        if 'UDP' in protocol_stack:
            dst_ip = protocol_stack['IP']['dst']
            self.udp_counter[dst_ip] += 1
            if self.udp_counter[dst_ip] > 1000:  # 임의의 임계값
                is_malicious = True
                reasons.append("DDoS UDP") #High number of UDP packets to same destination

        if is_malicious:
            packet_info['malicious'] = True
            packet_info['reasons'] = reasons
        else:
            packet_info['malicious'] = False

        return is_malicious

    def get_statistics(self):
        stream_stats = self.stream_analyzer.get_statistics()
        return {
            'total_packets': len(self.benign_packets) + len(self.malicious_packets),
            'benign_packets': len(self.benign_packets),
            'malicious_packets': len(self.malicious_packets),
            'stream_statistics': stream_stats
        }

    def save_to_json(self, benign_file: str, malicious_file: str):
        with open(benign_file, "w", encoding='utf-8') as f:
            json.dump(self.benign_packets, f, indent=2, ensure_ascii=False)
        with open(malicious_file, "w", encoding='utf-8') as f:
            json.dump(self.malicious_packets, f, indent=2, ensure_ascii=False)

def analyze_pcap(pcap_file: str, num_threads: int, output_benign: str, output_malicious: str):
    reader = ParallelPCAPReader(pcap_file, num_threads=num_threads)
    extractor = HeaderExtractor()

    reader.run()

    for packet in reader.get_processed_packets():
        extractor.process_packet(packet)

    extractor.save_to_json(output_benign, output_malicious)
    return extractor.get_statistics()

if __name__ == "__main__":
    pass