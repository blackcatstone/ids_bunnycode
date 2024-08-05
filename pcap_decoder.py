import os
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IPv6
from scapy.layers.dot11 import Dot11
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.packet import Packet as ScapyPacket
from typing import Dict, Any
import threading
from queue import Queue
from tqdm import tqdm

class Packet:
    def __init__(self, scapy_packet: ScapyPacket):
        self.timestamp = float(scapy_packet.time)
        self.protocol_stack = self.decode_protocol_stack(scapy_packet)
        self.length = len(scapy_packet)
        self.payload = self.extract_payload(scapy_packet)
        self.raw_packet = bytes(scapy_packet)

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
                    'proto': packet[IP].proto,
                    'ttl': packet[IP].ttl,
                    'flags': packet[IP].flags,
                    'frag': packet[IP].frag,
                    'tos': packet[IP].tos,
                    'id': packet[IP].id,
                    'ihl': packet[IP].ihl,
                    'len': packet[IP].len,
                    'chksum': packet[IP].chksum
                }
            elif IPv6 in packet:
                stack['IP'] = {
                    'version': 6,
                    'src': packet[IPv6].src,
                    'dst': packet[IPv6].dst,
                    'nh': packet[IPv6].nh,
                    'fl': packet[IPv6].fl,
                    'tc': packet[IPv6].tc,
                    'hlim': packet[IPv6].hlim,
                    'plen': packet[IPv6].plen
                }
            elif ARP in packet:
                stack['ARP'] = {
                    'hwtype': packet[ARP].hwtype,
                    'ptype': packet[ARP].ptype,
                    'hwlen': packet[ARP].hwlen,
                    'plen': packet[ARP].plen,
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
                    'dataofs': packet[TCP].dataofs,
                    'reserved': packet[TCP].reserved,
                    'flags': str(packet[TCP].flags),
                    'window': packet[TCP].window,
                    'chksum': packet[TCP].chksum,
                    'urgptr': packet[TCP].urgptr,
                    'options': packet[TCP].options
                }
            elif UDP in packet:
                stack['UDP'] = {
                    'sport': packet[UDP].sport,
                    'dport': packet[UDP].dport,
                    'len': packet[UDP].len,
                    'chksum': packet[UDP].chksum
                }
            elif ICMP in packet:
                stack['ICMP'] = {
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code,
                    'chksum': packet[ICMP].chksum,
                    'id': packet[ICMP].id if hasattr(packet[ICMP], 'id') else None,
                    'seq': packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else None
                }

            # Application Layer
            if packet.haslayer(HTTPRequest):
                try:
                    headers = {}
                    for header in packet[HTTPRequest].fields_desc:
                        field_name = header.name
                        headers[field_name] = str(getattr(packet[HTTPRequest], field_name))
                    
                    stack['HTTP'] = {
                        'method': packet[HTTPRequest].Method.decode() if packet[HTTPRequest].Method else None,
                        'host': packet[HTTPRequest].Host.decode() if packet[HTTPRequest].Host else None,
                        'path': packet[HTTPRequest].Path.decode() if packet[HTTPRequest].Path else None,
                        'headers': headers,
                        'body': packet[HTTPRequest].load.decode(errors='ignore') if Raw in packet else ''
                    }
                except Exception as e:
                    stack['error'] = f"Error decoding HTTP request: {type(e).__name__} - {str(e)}"
            elif packet.haslayer(HTTPResponse):
                try:
                    headers = {}
                    for header in packet[HTTPResponse].fields_desc:
                        field_name = header.name
                        headers[field_name] = str(getattr(packet[HTTPResponse], field_name))

                    stack['HTTP'] = {
                        'status_code': packet[HTTPResponse].Status_Code if hasattr(packet[HTTPResponse], 'Status_Code') else None,
                        'headers': headers,
                        'body': packet[HTTPResponse].load.decode(errors='ignore') if Raw in packet else ''
                    }
                except Exception as e:
                    stack['error'] = f"Error decoding HTTP response: {type(e).__name__} - {str(e)}"
            elif packet.haslayer(DNS):
                stack['DNS'] = {
                    'id': packet[DNS].id,
                    'qr': packet[DNS].qr,
                    'opcode': packet[DNS].opcode,
                    'questions': packet[DNS].qd,
                    'answers': packet[DNS].an,
                    'authorities': packet[DNS].ns,
                    'additional': packet[DNS].ar
                }
            elif packet.haslayer(SNMP):
                stack['SNMP'] = {
                    'version': packet[SNMP].version,
                    'community': packet[SNMP].community.decode('utf-8', errors='ignore'),
                    'pdu_type': packet[SNMP].PDU,
                    'variable_bindings': packet[SNMP].varbindlist
                }
            
            if UDP in packet and (packet[UDP].sport == 123 or packet[UDP].dport == 123):
                if packet.haslayer(NTP):
                    stack['NTP'] = {
                        'version': packet[NTP].version,
                        'mode': packet[NTP].mode,
                        'stratum': packet[NTP].stratum,
                        'poll': packet[NTP].poll,
                        'precision': packet[NTP].precision,
                        'root_delay': packet[NTP].rootdelay,
                        'root_dispersion': packet[NTP].rootdispersion,
                        'ref_id': packet[NTP].refid,
                        'ref_timestamp': packet[NTP].reftime,
                        'orig_timestamp': packet[NTP].origtime,
                        'recv_timestamp': packet[NTP].recvtime,
                        'trans_timestamp': packet[NTP].transtime
                    }
             
            # HTTPS (assuming it's over TCP port 443)
            if TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
                stack['HTTPS'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport,
                    'seq': packet[TCP].seq,
                    'ack': packet[TCP].ack,
                    'flags': str(packet[TCP].flags),
                    'window': packet[TCP].window,
                    'chksum': packet[TCP].chksum,
                    'urgptr': packet[TCP].urgptr,
                    'options': packet[TCP].options
                }
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        stack['HTTPS']['payload'] = payload
                    except Exception as e:
                        stack['HTTPS']['payload_error'] = f"Error decoding HTTPS payload: {type(e).__name__} - {str(e)}"
            
            # MQTT (assuming it's over TCP port 1883 for unencrypted or 8883 for encrypted)
            if TCP in packet and (packet[TCP].sport in [1883, 8883] or packet[TCP].dport in [1883, 8883]):
                stack['MQTT'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport,
                    'type': packet[Raw].load[0] >> 4 if Raw in packet else None,  # Extract the message type from the first byte
                    'flags': packet[Raw].load[0] & 0x0F if Raw in packet else None,  # Extract the flags from the first byte
                    'remaining_length': len(packet[Raw].load) - 1 if Raw in packet else None,  # Remaining length is the length of the packet minus the fixed header
                    'variable_header': packet[Raw].load[1:] if Raw in packet else '',  # Extract the variable header
                    'payload': packet[Raw].load[1:] if Raw in packet else ''
                }
            if TCP in packet and (packet[TCP].sport == 21 or packet[TCP].dport == 21):
                stack['FTP'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport
                }
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('USER ', 'PASS ', 'RETR ', 'STOR ')):
                        command, *arguments = payload.split()
                        stack['FTP']['command'] = command
                        stack['FTP']['arguments'] = ' '.join(arguments)
                        
            if TCP in packet and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
                stack['SSH'] = {
                    'sport': packet[TCP].sport,
                    'dport': packet[TCP].dport
                }
                if Raw in packet:
                    payload = packet[Raw].load
                    if b"SSH-" in payload:
                        stack['SSH']['version'] = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        
            if TCP in packet:
                payload = ''
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                if (packet[TCP].sport == 6667 or packet[TCP].dport == 6667) or \
                ('NICK ' in payload or 'JOIN #' in payload or 'PRIVMSG ' in payload):
                    stack['IRC'] = {
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport,
                        'command': payload.split()[0] if ' ' in payload else payload.strip(),
                        'params': ' '.join(payload.split()[1:]) if ' ' in payload else ''
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

    def _ensure_serializable(self, obj):
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
