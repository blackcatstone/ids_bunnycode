from pcap_decoder import ParallelPCAPReader
from network_stream import StreamAnalyzer
import json, os

def get_user_input():
    pcap_file = input("PCAP 파일 경로를 입력하세요: ")
    threads = int(input("처리할 스레드 수를 입력하세요 (기본값: 4): ") or "4")
    num_packets = int(input("분석할 패킷 수를 입력하세요 (0 입력 시 모든 패킷 분석): ") or "0")
    output_file = input("출력할 텍스트 파일 이름을 입력하세요: ")
    return pcap_file, threads, num_packets, output_file

def encode_payloads(streams):
    encoded_streams = {}
    for stream_id, stream in streams.items():
        encoded_streams[stream_id] = {
            'client': stream['client'].hex(),
            'server': stream['server'].hex()
        }
    return encoded_streams

def main():
    print("PCAP 파일 분석 프로그램에 오신 것을 환영합니다!\n")
    
    pcap_file, threads, num_packets, output_file = get_user_input()

    normalized_path = os.path.abspath(pcap_file)
    if not os.path.isfile(normalized_path):
        print(f"File not found: {pcap_file}")
        print(f"Also check your current working directory: {os.getcwd()}")
        return

    reader = ParallelPCAPReader(normalized_path, num_threads=threads)
    network_analyzer = StreamAnalyzer()
    
    print("\nPCAP 파일 읽기 및 패킷 처리 중...")
    reader.run()

    total_packets = reader.get_total_packets()
    print(f"\n총 패킷 수: {total_packets}")

    with open(output_file, 'w') as f:
        for i, packet in enumerate(reader.get_processed_packets()):
            if num_packets != 0 and i >= num_packets:
                break
            
            packet_dict = packet.to_dict()
            f.write(f"Packet {i+1}:\n")
            json.dump(packet_dict, f, indent=2)
            f.write("\n")

            network_analyzer.process_packet(packet_dict)

    all_streams = network_analyzer.get_all_streams()

     # TCP 스트림을 JSON 파일로 저장    
    with open(f'{output_file}_tcp.json', 'w', encoding='utf-8') as file:
        json.dump(all_streams['tcp'], file, indent=4, ensure_ascii=False)

    # UDP 그룹을 JSON 파일로 저장
    with open(f'{output_file}_udp.json', 'w', encoding='utf-8') as file:
        json.dump(all_streams['udp'], file, indent=4, ensure_ascii=False)

    print(f"\n분석 완료: {min(num_packets, total_packets) if num_packets != 0 else total_packets}개의 패킷을 분석했습니다.")

    stats = network_analyzer.get_statistics()
    print(f"총 스트림 수: {stats['total_tcp_streams']}")
    print(f"총 UDP 그룹 수: {stats['total_udp_groups']}")

    print(f"\n결과가 {output_file}, {output_file}_tcp.json, {output_file}_udp.json에 저장되었습니다.")

if __name__ == "__main__":
    main()
