import json
import csv
import sys
from datetime import datetime
import os

def parse_log(input_file, output_file):
    with open(input_file, 'r') as infile:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'category', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'payload', 'action']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for line_number, line in enumerate(infile, start=1):
                try:
                    log = json.loads(line.strip())
                except json.JSONDecodeError:
                    print(f"Skipping malformed JSON line {line_number}")
                    continue

                # 'signature_id' 필드가 있는 경우, 해당 로그를 CSV에 기록
                if 'signature_id' in log.get('alert', {}):
                    timestamp = datetime.strptime(log['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d %H:%M")
                    category = log['alert'].get('category', 'Unknown')
                    msg = log['alert'].get('signature', 'Unknown')

                    if not category:
                        category = msg
                    
                    src_ip = log.get('src_ip', 'Unknown')
                    src_port = log.get('src_port', 'Unknown')
                    dest_ip = log.get('dest_ip', 'Unknown')
                    dest_port = log.get('dest_port', 'Unknown')
                    payload = log.get('payload_printable', '')  # payload가 없을 경우 빈 문자열
                    action = 'ALERT' if log['alert'].get('action') == 'allowed' else 'DROP'

                    writer.writerow({
                        'timestamp': timestamp,
                        'category': category,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dest_ip': dest_ip,
                        'dest_port': dest_port,
                        'payload': payload,
                        'action': action
                    })

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 logparser.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    
    output_directory = '/Users/user/Downloads/csv'  # csv가 저장 경로를 입력하세요.

    output_file = os.path.join(output_directory, os.path.splitext(os.path.basename(input_file))[0][3:] + '.csv')
    
    parse_log(input_file, output_file)
    print(f"CSV file saved as {output_file}")
