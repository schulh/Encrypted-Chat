#!/usr/bin/env python3
import threading
import socket
import ssl
import argparse
from colors import bcolors
import time



class SSLServer(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        print(bcolors.OKGREEN + "[+] New connection from " + str(conn) + bcolors.ENDC)

    def run(self):
        print(bcolors.OKBLUE + "STARTED NEW THREAD"  + bcolors.ENDC)
        data = "Client " + str(addr) + " connected"
        SSLServer.broadcast(self, data, self.conn, self.addr)
        while True:
            data = self.conn.recv(buffer_size).decode()
            if data:
                SSLServer.broadcast(self, data, self.conn, self.addr)
            else:
                if conn in socketList:
                    socketList.remove(conn)
                    print(bcolors.FAIL + "[!] removed " + str(conn) + bcolors.ENDC)
                    data = "Client " + str(addr) + "disconnected"
                    SSLServer.broadcast(self, data, self.conn, self.addr)

    def broadcast(self, data, conn, addr):
        #print(bcolors.OKGREEN + "SOCKET LIST: \n"  + bcolors.ENDC)
        #print(bcolors.OKGREEN + str(socketList) + bcolors.ENDC)
        for i in range(0, len(socketList)):
            if socketListPort[i] != addr[1]:
                #data = str(addr) + ": " + data
                socketList[i].send(data.encode())
                print("Message sent to: " + str(socketListPort[i]))
                #print(str(len(socketListPort)))


parser = argparse.ArgumentParser()
parser.add_argument("--verbosity", help="increase output verbosity")
parser.add_argument("--ip", help="listening ip")
parser.add_argument("--port", help="listening port", type=int)
args = parser.parse_args()
if args.verbosity:
    print("verbosity turned on")

if args.ip:
    ip = args.ip
else:
    ip = '127.0.0.1'
if args.port:
    port = args.port
else:
    port = 50000

buffer_size = 2048




sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket = ssl.wrap_socket(sock,keyfile='certs/ca.key', certfile='certs/ca.crt', \
cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2, \
ciphers='ECDH', do_handshake_on_connect=True)
mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mySocket.bind((ip,port))
threads = []
socketListPort = []
socketList = []


while True:
    mySocket.listen(4)
    conn, addr = mySocket.accept()
    socketListPort.append(addr[1])
    socketList.append(conn)
    newThread = SSLServer(conn, addr)
    newThread.start()
    threads.append(newThread)
for t in threads:
    t.join()
