# app_layer.py

def classify_app_layer(packet):
    """
    Classify the application layer protocol for a given packet.
    
    :param packet: A dictionary representing packet data.
    :return: A string representing the application layer protocol.
    """
    payload = packet.get('payload', b'')
    
    if payload.startswith(b'HTTP/'):
        return 'HTTP'
    elif payload.startswith(b'\x16\x03'):  # TLS handshake record
        return 'TLS'
    elif payload.startswith(b'SSH-'):
        return 'SSH'
    elif payload.startswith(b'\x00\x01'):  # DNS query
        return 'DNS'
    else:
        return 'Unknown'

def is_malicious(packet):
    """
    Determine if a packet is malicious based on some basic rules.
    
    :param packet: A dictionary representing packet data.
    :return: A boolean indicating if the packet is malicious.
    """
    src_ip = packet.get('src_ip')
    dest_ip = packet.get('dest_ip')
    src_port = packet.get('src_port')
    dest_port = packet.get('dest_port')
    payload = packet.get('payload', b'')

    # Example rule: Check for a known malicious IP address
    known_malicious_ips = {'192.168.1.10', '10.0.0.5'}
    if src_ip in known_malicious_ips or dest_ip in known_malicious_ips:
        return True

    # Example rule: Check for unusual ports
    if src_port == 4444 or dest_port == 4444:
        return True

    # Example rule: Check for specific payload signatures
    if b'malicious_pattern' in payload:
        return True

    return False

def process_packets(packets):
    """
    Process a list of packets and classify each one.
    
    :param packets: A list of packet dictionaries.
    :return: A list of tuples (packet, app_layer_classification, is_malicious).
    """
    processed_packets = []
    for packet in packets:
        app_layer_classification = classify_app_layer(packet)
        malicious = is_malicious(packet)
        processed_packets.append((packet, app_layer_classification, malicious))
    return processed_packets
