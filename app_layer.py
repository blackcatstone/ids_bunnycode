from pcap_decoder import ParallelPCAPReader, Packet
from typing import Dict, Any
import json
from collections import defaultdict
import re

class AppLayerAnalyzer:
    def __init__(self):
        self.benign_packets = []
        self.malicious_packets = []
        self.attack_counters = defaultdict(int)
        self.dns_queries = defaultdict(list)
        self.dns_responses = defaultdict(list)

    def process_packet(self, packet: Packet):
        packet_info = packet.to_dict()
        
        if self.is_malicious(packet_info):
            self.malicious_packets.append(packet_info)
        else:
            self.benign_packets.append(packet_info)

    def is_malicious(self, packet_info: Dict[str, Any]) -> bool:
        is_malicious = False
        reasons = []

        protocol_stack = packet_info['protocol_stack']
        
        # Helper function to increment counters
        def increment_counter(ip):
            self.attack_counters[ip] += 1
            return self.attack_counters[ip]

        # Detect DDoS HTTP Flood
        if 'HTTP' in protocol_stack and protocol_stack['HTTP'].get('method') in ['GET', 'POST']:
            dst_ip = protocol_stack['IP']['dst']
            if increment_counter(dst_ip) > 100:  # Arbitrary threshold
                is_malicious = True
                reasons.append("DDoS HTTP Flooding")

        if 'DNS' in protocol_stack and protocol_stack['DNS'].get('qr') == 0:  # QR=0 means a query
            src_ip = protocol_stack['IP']['src']
            self.attack_counters[src_ip] += 1
            if self.attack_counters[src_ip] > 50:  # Arbitrary threshold
                is_malicious = True
                reasons.append("DNS Spoofing")

        if 'DNS' in protocol_stack:
            dns = protocol_stack['DNS']
            src_ip = protocol_stack['IP']['src']
            query_name = dns['questions'][0].qname.decode() if dns['questions'] and hasattr(dns['questions'][0], 'qname') else None
            
            if dns['qr'] == 0:  # DNS query
                self.dns_queries[query_name].append(packet_info)
            elif dns['qr'] == 1:  # DNS response
                if hasattr(dns, 'answers'):
                    for answer in dns['answers']:
                        if hasattr(answer, 'type') and answer.type == 1:  # DNS A record
                            self.dns_responses[query_name].append((answer.rdata, packet_info))

            # Analyze DNS responses for inconsistencies
            ip_addresses = set()
            for ip, _ in self.dns_responses[query_name]:
                ip_addresses.add(ip)
                if len(ip_addresses) > 1:  # More than one IP for the same query
                    is_malicious = True
                    reasons.append(f"DNS Spoofing for {query_name}")

        # Detect DDoS HTTPS Flooding
        if 'HTTPS' in protocol_stack:
            dst_ip = protocol_stack['IP']['dst']
            if increment_counter(dst_ip) > 100:  # Arbitrary threshold
                is_malicious = True
                reasons.append("DDoS HTTPS Flooding")

        # Detect GET Flooding
        if 'HTTP' in protocol_stack and protocol_stack['HTTP'].get('method') == 'GET':
            dst_ip = protocol_stack['IP']['dst']
            if increment_counter(dst_ip) > 200:  # Arbitrary threshold for GET flood
                is_malicious = True
                reasons.append("GET Flooding")

        # Detect HTTP Fuzzing
        if 'HTTP' in protocol_stack and protocol_stack['HTTP'].get('method') in ['GET', 'POST']:
            path = protocol_stack['HTTP'].get('path', '')
            if re.search(r'(\.\./|\.\.\\|%00|%2e%2e%2f|%2e%2e%5c)', path):
                is_malicious = True
                reasons.append("HTTP Fuzzing")

        # Detect SQL Injection
        if 'HTTP' in protocol_stack and protocol_stack['HTTP'].get('method') in ['GET', 'POST']:
            path = protocol_stack['HTTP'].get('path', '')
            if re.search(r'(\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\b--\b|/\*|\*/|\bOR\b\s+\b1\b\s*=\s*\b1\b|\bAND\b\s+\b1\b\s*=\s*\b1\b|\' OR 1=1|\' AND 1=1)', path, re.IGNORECASE):
                is_malicious = True
                reasons.append("SQL Injection")

        # Detect XSS (Cross-Site Scripting)
        if 'HTTP' in protocol_stack and protocol_stack['HTTP'].get('method') in ['GET', 'POST']:
            path = protocol_stack['HTTP'].get('path', '')
            if re.search(r'(<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>)', path, re.IGNORECASE):
                is_malicious = True
                reasons.append("XSS")

        if is_malicious:
            packet_info['malicious'] = True
            packet_info['reasons'] = reasons
        else:
            packet_info['malicious'] = False

        return is_malicious

    def save_to_json(self, benign_file: str, malicious_file: str):
        with open(benign_file, "w", encoding='utf-8') as f:
            json.dump(self.benign_packets, f, indent=2, ensure_ascii=False)
        with open(malicious_file, "w", encoding='utf-8') as f:
            json.dump(self.malicious_packets, f, indent=2, ensure_ascii=False)

def analyze_pcap(pcap_file: str, num_threads: int, num_packets: int, output_benign: str, output_malicious: str):
    reader = ParallelPCAPReader(pcap_file, num_threads=num_threads)
    analyzer = AppLayerAnalyzer()

    reader.run()

    packets_to_process = reader.get_processed_packets()
    if num_packets != 0:
        packets_to_process = packets_to_process[:num_packets]

    for packet in packets_to_process:
        analyzer.process_packet(packet)

    analyzer.save_to_json(output_benign, output_malicious)
    return {
        'total_packets': len(analyzer.benign_packets) + len(analyzer.malicious_packets),
        'benign_packets': len(analyzer.benign_packets),
        'malicious_packets': len(analyzer.malicious_packets)
    }

if __name__ == "__main__":
    pass
