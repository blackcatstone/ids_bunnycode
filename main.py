
from pcap_decoder import ParallelPCAPReader
import json
import time
from tqdm import tqdm

def get_user_input():
    pcap_file = input("PCAP 파일 경로를 입력하세요: ")
    threads = int(input("처리할 스레드 수를 입력하세요 (기본값: 4): ") or "4")
    num_packets = int(input("분석할 패킷 수를 입력하세요 (0 입력 시 모든 패킷 분석): ") or "0")
    output_file = input("출력할 텍스트 파일 이름을 입력하세요: ")
    return pcap_file, threads, num_packets, output_file

def main():
    print("PCAP 파일 분석 프로그램에 오신 것을 환영합니다!")
    
    pcap_file, threads, num_packets, output_file = get_user_input()

    reader = ParallelPCAPReader(pcap_file, num_threads=threads)
    
    print("PCAP 파일 읽기 및 패킷 처리 중...")
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
            f.write("\n\n")

    print(f"\n분석 완료: {min(num_packets, total_packets) if num_packets != 0 else total_packets}개의 패킷을 분석했습니다.")
    print(f"결과가 {output_file}에 저장되었습니다.")

if __name__ == "__main__":
    main()