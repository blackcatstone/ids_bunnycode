from collections import defaultdict
from typing import Dict, Tuple, Any

class TCPStream:
    def __init__(self):
        self.streams: Dict[Tuple, Dict] = defaultdict(lambda: {'client': {}, 'server': {}})

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

            # stream 식별자 생성
            stream_id = self._get_stream_id(src_ip, dst_ip, src_port, dst_port)
            stream = self.streams[stream_id]

            # 패킷 방향 및 seq 넘버를 기준으로 페이로드 저장 (중복된 패킷 제거)
            payload = bytes.fromhex(packet_info.get('payload', ''))
            if stream_id[0] == src_ip and stream_id[2] == src_port: # 클라이언트로부터 온 패킷
                direction = 'client'
            else: # 서버로부터 온 패킷
                direction = 'server'
            stream[direction][seq] = payload

            # 패킷 재조합
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
            # 패킷 순서 조정
            sorted_seqs = sorted(stream[direction].keys())
            
            # 페이로드 연결 (중복 제거)
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

class TCPStreamAnalyzer:
    def __init__(self):
        self.tcp_stream = TCPStream()

    def process_packet(self, packet_info: Dict[str, Any]):
        return self.tcp_stream.process_packet(packet_info)

    def get_statistics(self):
        return {
            'total_streams': self.tcp_stream.get_stream_count()
        }
    
    def get_all_streams(self):
        return self.tcp_stream.get_all_streams()