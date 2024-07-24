import os
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IPv6
from scapy.layers.dot11 import Dot11
from scapy.packet import Packet as ScapyPacket
from typing import Dict, Any, Optional
import threading
from queue import Queue
from tqdm import tqdm

class Packet:
    def __init__(self, scapy_packet: ScapyPacket):
        self.timestamp = float(scapy_packet.time)
        self.protocol_stack = self.decode_protocol_stack(scapy_packet)
        self.length = len(scapy_packet)
        self.payload = self.extract_payload(scapy_packet)

    def decode_protocol_stack(self, packet: ScapyPacket) -> Dict[str, Any]:
        stack = {}
        
        try:
            # Link Layer
            if Ether in packet:
                stack['Ethernet'] = {
                    'src': packet[Ether].src,
                    'dst': packet[Ether].dst,
                    'type': packet[Ether].type
                }
            elif Dot11 in packet:
                stack['WiFi'] = {
                    'type': packet[Dot11].type,
                    'subtype': packet[Dot11].subtype
                }

            # Network Layer
            if IP in packet:
                stack['IP'] = {
                    'version': 4,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'proto': packet[IP].proto
                }
            elif IPv6 in packet:
                stack['IP'] = {
                    'version': 6,
                    'src': packet[IPv6].src,
                    'dst': packet[IPv6].dst,
                    'nh': packet[IPv6].nh
                }
            elif ARP in packet:
                stack['ARP'] = {
                    'op': packet[ARP].op,
                    'hwsrc': packet[ARP].hwsrc,
                    'psrc': packet[ARP].psrc,
                    'hwdst': packet[ARP].hwdst,
                    'pdst': packet[ARP].pdst
                }

            # Transport Layer
            if TCP in packet:
                stack['TCP'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport,
                    'seq': packet[TCP].seq,
                    'ack': packet[TCP].ack,
                    'flags': str(packet[TCP].flags)
                }
            elif UDP in packet:
                stack['UDP'] = {
                    'sport': packet[UDP].sport,
                    'dport': packet[UDP].dport,
                    'len': packet[UDP].len
                }
            elif ICMP in packet:
                stack['ICMP'] = {
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code
                }

            # Application Layer
            if packet.haslayer(HTTP):
                stack['HTTP'] = {
                    'method': packet[HTTP].Method.decode() if packet[HTTP].Method else None,
                    'path': packet[HTTP].Path.decode() if packet[HTTP].Path else None,
                    'status_code': packet[HTTP].Status_Code if hasattr(packet[HTTP], 'Status_Code') else None
                }
            elif packet.haslayer(DNS):
                stack['DNS'] = {
                    'id': packet[DNS].id,
                    'qr': packet[DNS].qr,
                    'opcode': packet[DNS].opcode
                }
            
            # HTTPS (assuming it's over TCP port 443)
            if TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
                stack['HTTPS'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport
                }
            
            # MQTT (assuming it's over TCP port 1883 for unencrypted or 8883 for encrypted)
            if TCP in packet and (packet[TCP].sport in [1883, 8883] or packet[TCP].dport in [1883, 8883]):
                stack['MQTT'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport
                }
        except Exception as e:
            stack['error'] = f"Error decoding packet: {str(e)}"

        return stack

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'protocol_stack': self._ensure_serializable(self.protocol_stack),
            'length': self.length,
            'payload': self.payload.hex()
        }
    def _ensure_serializable(self, obj): #분석된걸 텍스트파일로 확인하기 위해 넣은 것이기에 나중에 없앨 가능성 있음
        if isinstance(obj, dict):
            return {k: self._ensure_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._ensure_serializable(v) for v in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)
        
    def extract_payload(self, packet: ScapyPacket) -> bytes:
        while packet.payload:
            packet = packet.payload
        return bytes(packet)

class ParallelPCAPReader:
    def __init__(self, filename: str, num_threads: int = 4):
        if not os.path.isfile(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        self.filename = filename
        self.num_threads = num_threads
        self.packet_queue = Queue(maxsize=1000)
        self.result_queue = Queue()
        self.total_packets = 0
        self.processed_packets = 0
        self.file_size = os.path.getsize(filename)

    def read_packets(self):
        try:
            with PcapReader(self.filename) as pcap_reader:
                pbar = tqdm(total=self.file_size, unit='B', unit_scale=True, desc="Reading PCAP")
                for packet in pcap_reader:
                    self.packet_queue.put(packet)
                    self.total_packets += 1
                    pbar.update(len(packet))
                pbar.close()
        except Exception as e:
            raise e
        
        for _ in range(self.num_threads):
            self.packet_queue.put(None)

    def process_packets(self):
        while True:
            try:
                scapy_packet = self.packet_queue.get()
                if scapy_packet is None:
                    self.packet_queue.put(None)
                    break
                
                packet = Packet(scapy_packet)
                self.result_queue.put(packet)
                self.processed_packets += 1
            except Exception as e:
                print(f"Error processing packet: {str(e)}")
                continue

    def run(self):
        read_thread = threading.Thread(target=self.read_packets)
        read_thread.start()

        process_threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.process_packets)
            t.start()
            process_threads.append(t)

        read_thread.join()
        for t in process_threads:
            t.join()

    def get_processed_packets(self):
        pbar = tqdm(total=self.total_packets, desc="Processing packets")
        while not self.result_queue.empty():
            yield self.result_queue.get()
            pbar.update(1)
        pbar.close()
    
    def get_total_packets(self):
        return self.total_packets

    def get_progress(self):
        return self.processed_packets / self.total_packets if self.total_packets > 0 else 0

if __name__ == "__main__":
    pass
