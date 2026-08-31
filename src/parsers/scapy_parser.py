"""Direct PCAP to Parquet conversion using Scapy (no tshark required).\n\nThis module parses PCAP files using the Scapy packet manipulation library\nand extracts structured packet metadata into Python dictionaries compatible\nwith the application's Parquet schema.\n\nExtracted fields per packet:\n    - frame_no, timestamp, src_ip, dst_ip\n    - src_port, dst_port, protocol, length\n    - info (human-readable summary), protocols (colon-separated stack)\n\nNo external tools (like tshark) are required -- pure Python parsing.\n"""
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from datetime import datetime
import json

def parse_pcap_with_scapy(pcap_path: str) -> list:
    """
    Parse PCAP file using Scapy and return list of packet dictionaries
    Compatible with the Parquet schema expected by the application
    """
    packets = []
    
    try:
        print(f"[INFO] Reading PCAP with Scapy: {pcap_path}")
        scapy_packets = rdpcap(pcap_path)
        print(f"[INFO] Found {len(scapy_packets)} packets")
        
        for idx, pkt in enumerate(scapy_packets, start=1):
            packet_dict = {
                'frame_no': idx,
                'timestamp': float(pkt.time),
                'src_ip': '',
                'dst_ip': '',
                'src_port': 0,
                'dst_port': 0,
                'protocol': '',
                'length': len(pkt),
                'info': '',
                'protocols': []
            }
            
            # Extract IP layer info
            if IP in pkt:
                packet_dict['src_ip'] = pkt[IP].src
                packet_dict['dst_ip'] = pkt[IP].dst
                packet_dict['protocols'].append('IP')
                
                # Extract TCP info
                if TCP in pkt:
                    packet_dict['src_port'] = pkt[TCP].sport
                    packet_dict['dst_port'] = pkt[TCP].dport
                    packet_dict['protocol'] = 'TCP'
                    packet_dict['protocols'].append('TCP')
                    
                    # TCP flags info
                    flags = []
                    if pkt[TCP].flags.S: flags.append('SYN')
                    if pkt[TCP].flags.A: flags.append('ACK')
                    if pkt[TCP].flags.F: flags.append('FIN')
                    if pkt[TCP].flags.R: flags.append('RST')
                    if pkt[TCP].flags.P: flags.append('PSH')
                    
                    packet_dict['info'] = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport} [{','.join(flags)}]"
                
                # Extract UDP info
                elif UDP in pkt:
                    packet_dict['src_port'] = pkt[UDP].sport
                    packet_dict['dst_port'] = pkt[UDP].dport
                    packet_dict['protocol'] = 'UDP'
                    packet_dict['protocols'].append('UDP')
                    packet_dict['info'] = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
                
                # Check for HTTP-like content
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HTTP')):
                            packet_dict['protocols'].append('HTTP')
                            first_line = payload_str.split('\r\n')[0]
                            packet_dict['info'] = first_line[:100]
                    except:
                        pass
            
            # Convert protocols list to string
            packet_dict['protocols'] = ':'.join(packet_dict['protocols']) if packet_dict['protocols'] else 'Unknown'
            
            packets.append(packet_dict)
    
    except Exception as e:
        print(f"[ERROR] Failed to parse PCAP with Scapy: {e}")
        raise
    
    return packets
