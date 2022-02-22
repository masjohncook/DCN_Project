#!/usr/bin/python3

import socket

HOST = '<SERVER_IP_ADDRESS>'
PORT = 1234
BUFFER_SIZE = 1024
MESSAGE = "<Student ID>"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print('send: ' + MESSAGE)
s.send(MESSAGE.encode())
data = s.recv(BUFFER_SIZE)
print('recv: ' + data.decode())
s.close(