#!/usr/bin/python3

import socket

HOST = '<Server_IP_Address>'
PORT = 1234
BUFFER_SIZE = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

conn, addr = s.accept()
print("connection address: " + str(addr))

while True:
    data = conn.recv(BUFFER_SIZE)
    if not  data:
        print('Client close connection')
        break
    print('recv: ' + data.decode())
    out_data = 'echo: ' + data.decode()
    conn.send(out_data.encode())
conn.close()
