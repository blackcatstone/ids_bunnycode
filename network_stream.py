from collections import defaultdict
from typing import Dict, Tuple, Any, List
import string

class TCPStream:
    def __init__(self):
        self.streams: Dict[Tuple, Dict] = defaultdict(lambda: {'client': {}, 'server': {}})
        self.lost_packets: Dict[Tuple, List[int]] = defaultdict(list)

    def process_packet(self, packet_info: Dict[str, Any]):
        protocol_stack = packet_info['protocol_stack']
        
        if 'TCP' in protocol_stack:
            ip_layer = protocol_stack.get('IP', protocol_stack.get('IPv6'))
            if not ip_layer:
                return None

            tcp_layer = protocol_stack['TCP']
            src_ip, dst_ip = ip_layer['src'], ip_layer['dst']
            src_port, dst_port = tcp_layer['sport'], tcp_layer['dport']
            seq = tcp_layer['seq']

            stream_id = self._get_stream_id(src_ip, dst_ip, src_port, dst_port)
            stream = self.streams[stream_id]

            payload = bytes.fromhex(packet_info.get('payload', ''))
            if stream_id[0] == src_ip and stream_id[2] == src_port:
                direction = 'client'
            else:
                direction = 'server'

            # 중복 패킷 처리
            if seq in stream[direction]:
                if len(payload) > len(stream[direction][seq]):
                    stream[direction][seq] = payload
            else:
                stream[direction][seq] = payload

            # 누락된 패킷 확인
            expected_seq = max(stream[direction].keys()) + len(stream[direction][max(stream[direction].keys())]) if stream[direction] else seq
            if seq > expected_seq:
                self.lost_packets[stream_id].append(expected_seq)

            reassembled = self._reassemble_stream(stream)
            return reassembled

        return None

    def _get_stream_id(self, src_ip, dst_ip, src_port, dst_port):
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        else:
            return (dst_ip, src_ip, dst_port, src_port)

    def _reassemble_stream(self, stream):
        reassembled = {'client': b'', 'server': b''}
        for direction in ['client', 'server']:
            sorted_seqs = sorted(stream[direction].keys())
            assembled = b''
            expected_seq = sorted_seqs[0] if sorted_seqs else 0
            for seq in sorted_seqs:
                payload = stream[direction][seq]
                if seq >= expected_seq:
                    offset = seq - expected_seq
                    assembled += payload[offset:]
                    expected_seq = seq + len(payload)
            
            reassembled[direction] = assembled

        return reassembled

    def get_stream_count(self):
        return len(self.streams)
    
    def get_all_streams(self):
        return {str(stream_id): self._reassemble_stream(stream) for stream_id, stream in self.streams.items()}

    def get_lost_packets(self):
        return {str(stream_id): lost_seqs for stream_id, lost_seqs in self.lost_packets.items()}

class UDPGroup:
    def __init__(self):
        self.groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)

    def process_packet(self, packet_info: Dict[str, Any]):
        protocol_stack = packet_info['protocol_stack']
        
        if 'UDP' in protocol_stack:
            ip_layer = protocol_stack.get('IP', protocol_stack.get('IPv6'))
            if not ip_layer:
                return None

            udp_layer = protocol_stack['UDP']
            src_ip, dst_ip = ip_layer['src'], ip_layer['dst']
            src_port, dst_port = udp_layer['sport'], udp_layer['dport']

            group_id = self._get_group_id(src_ip, dst_ip, src_port, dst_port)

            payload = bytes.fromhex(packet_info.get('payload', ''))
            self.groups[group_id].append({
                'timestamp': packet_info['timestamp'],
                'length': len(payload),
                'payload': payload
            })

            return self.groups[group_id]

        return None

    def _get_group_id(self, src_ip, dst_ip, src_port, dst_port):
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        else:
            return (dst_ip, src_ip, dst_port, src_port)

    def get_group_count(self):
        return len(self.groups)
    
    def get_all_groups(self):
        return {str(group_id): group for group_id, group in self.groups.items()}

    def get_group_statistics(self):
        stats = {}
        for group_id, packets in self.groups.items():
            stats[str(group_id)] = {
                'packet_count': len(packets),
                'total_bytes': sum(p['length'] for p in packets),
                'avg_packet_size': sum(p['length'] for p in packets) / len(packets) if packets else 0,
                'time_span': packets[-1]['timestamp'] - packets[0]['timestamp'] if len(packets) > 1 else 0
            }
        return stats

class StreamAnalyzer:
    def __init__(self):
        self.tcp_stream = TCPStream()
        self.udp_group = UDPGroup()

    def process_packet(self, packet_info: Dict[str, Any]):
        tcp_result = self.tcp_stream.process_packet(packet_info)
        udp_result = self.udp_group.process_packet(packet_info)
        return tcp_result or udp_result

    def get_statistics(self):
        return {
            'total_tcp_streams': self.tcp_stream.get_stream_count(),
            'total_udp_groups': self.udp_group.get_group_count(),
            'udp_group_statistics': self.udp_group.get_group_statistics(),
            'tcp_lost_packets': self.tcp_stream.get_lost_packets()
        }
    
    def _make_printable(self, data):
        if not data:  # 데이터가 비어있으면 빈 문자열 반환
            return ""
        
        try:
            # UTF-8로 디코딩 시도
            decoded = data.decode('utf-8')
            # 읽을 수 있는 문자의 비율 계산
            readable_ratio = sum(c in string.printable for c in decoded) / len(decoded)
            
            if readable_ratio > 0.7:  # 70% 이상이 읽을 수 있는 문자라면
                return decoded
        except UnicodeDecodeError:
            pass  # UTF-8 디코딩 실패 시 다음 단계로

        # ASCII 문자로 변환 시도
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        
        # 읽을 수 있는 문자의 비율 계산
        readable_ratio = sum(c in string.printable for c in printable) / len(printable)
        
        if readable_ratio > 0.7:  # 70% 이상이 읽을 수 있는 문자라면
            return printable
        else:
            # 16진수 표현을 개선된 형태로 반환
            return ' '.join(f'{b:02x}' for b in data)
    
    def get_all_streams(self):
        tcp_streams = self.tcp_stream.get_all_streams()
        udp_groups = self.udp_group.get_all_groups()

        for stream_id, stream in tcp_streams.items():
            for direction in ['client', 'server']:
                tcp_streams[stream_id][direction] = self._make_printable(stream[direction])

        for group_id, packets in udp_groups.items():
            for i, packet in enumerate(packets):
                udp_groups[group_id][i]['payload'] = self._make_printable(packet['payload'])

        return {
            'tcp': tcp_streams,
            'udp': udp_groups
        }
        
    def get_network_layer_statistics(self):
        stats = {
            'IP': {'count': 0, 'avg_ttl': 0, 'fragmented': 0},
            'IPv6': {'count': 0, 'avg_hlim': 0},
            'ARP': {'count': 0}
        }
        
        for stream in self.tcp_stream.streams.values():
            for packet in stream['client'].values():
                if isinstance(packet, dict) and 'protocol_stack' in packet:
                    protocol_stack = packet['protocol_stack']
                    if 'IP' in protocol_stack:
                        stats['IP']['count'] += 1
                        stats['IP']['avg_ttl'] += protocol_stack['IP']['ttl']
                        if protocol_stack['IP']['flags'] & 0x1:  # More fragments flag
                            stats['IP']['fragmented'] += 1
                    elif 'IPv6' in protocol_stack:
                        stats['IPv6']['count'] += 1
                        stats['IPv6']['avg_hlim'] += protocol_stack['IPv6']['hlim']
                    elif 'ARP' in protocol_stack:
                        stats['ARP']['count'] += 1
        
        if stats['IP']['count'] > 0:
            stats['IP']['avg_ttl'] /= stats['IP']['count']
        if stats['IPv6']['count'] > 0:
            stats['IPv6']['avg_hlim'] /= stats['IPv6']['count']
        
        return stats
    
    def get_transport_layer_statistics(self):
        stats = {
            'TCP': {'count': 0, 'avg_window_size': 0},
            'UDP': {'count': 0},
            'ICMP': {'count': 0, 'type_distribution': {}}
        }
        
        for stream in self.tcp_stream.streams.values():
            for packet in stream['client'].values():
                if 'TCP' in packet.protocol_stack:
                    stats['TCP']['count'] += 1
                    stats['TCP']['avg_window_size'] += packet.protocol_stack['TCP']['window']
                elif 'UDP' in packet.protocol_stack:
                    stats['UDP']['count'] += 1
                elif 'ICMP' in packet.protocol_stack:
                    stats['ICMP']['count'] += 1
                    icmp_type = packet.protocol_stack['ICMP']['type']
                    stats['ICMP']['type_distribution'][icmp_type] = stats['ICMP']['type_distribution'].get(icmp_type, 0) + 1
        
        if stats['TCP']['count'] > 0:
            stats['TCP']['avg_window_size'] /= stats['TCP']['count']
        
        return stats
    
    def get_enhanced_statistics(self):
        basic_stats = self.get_statistics()
        network_stats = self.get_network_layer_statistics()
        transport_stats = self.get_transport_layer_statistics()
        
        return {
            **basic_stats,
            'network_layer': network_stats,
            'transport_layer': transport_stats
        }
