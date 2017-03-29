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
        if args.verbosity == 1:
            print(bcolors.OKGREEN + "[+] New connection from " + str(conn) + bcolors.ENDC)

    def run(self):
        if args.verbosity == 1:
            print(bcolors.OKBLUE + "STARTED NEW THREAD"  + bcolors.ENDC)
        user = self.conn.recv(buffer_size).decode()
        activeUser.append(user)
        data = "[+]" + str(user) + " connected"
        self.broadcast(data, self.conn, self.addr, 0)
        welcomemsg = "Welcome " + user + "!\n" + "Active User: " + ",".join(users)
        self.broadcast(welcomemsg, self.conn, self.addr, 1)
        while True:
            data = self.conn.recv(buffer_size).decode()
            if args.verbosity == 1:
                print(data)
            if data:
                data2 = str(data).split(" ")
                if data2[1].startswith("/") == True:
                    if args.verbosity == 1:
                        print("[!] received command")
                    data2 = data2[1][1:]
                    command = self.serverCommands(str(data2))
                    command = "["+data2"]" + " " + command
                    self.broadcast(command, self.conn, self.addr, 1)
                else:
                    self.broadcast(data, self.conn, self.addr, 0)
            else:
                if conn in socketList:
                    socketList.remove(conn)
                    if args.verbosity == 1:
                        print(bcolors.FAIL + "[!] removed " + str(conn) + bcolors.ENDC)
                    data = "[-] " + str(user) + "disconnected"
                    SSLServer.broadcast(self, data, self.conn, self.addr, 0)

    def serverCommands(self, command):
        if args.verbosity == 1:
            print("[CMD] " + command)
        help = "There is no help..."
        if command == 'help':
            return help
        if command == 'user':
            users = activeUser
            users = ",".join(users)
            return users
        else:
            return "not found"



    def broadcast(self, data, conn, addr, flag):
        #print(bcolors.OKGREEN + "SOCKET LIST: \n"  + bcolors.ENDC)
        #print(bcolors.OKGREEN + str(socketList) + bcolors.ENDC)
        for i in range(0, len(socketList)):
            if socketListPort[i] != addr[1] and flag == 0:
                try:
                    socketList[i].send(data.encode())
                    if args.verbosity == 1:
                        print("Message sent to: " + str(socketListPort[i]))
                except BrokenPipeError:
                    conn.close()
            elif socketListPort[i] == addr[1] and flag == 1:
                try:
                    socketList[i].send(data.encode())
                    if args.verbosity == 1:
                        print("Message sent to: " + str(socketListPort[i]))
                except BrokenPipeError:
                    conn.close()



parser = argparse.ArgumentParser()
parser.add_argument("--verbosity", "-v", action='count', help="increase output verbosity")
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



"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sslsocket = ssl.SSLContext(protocol=1)
sslsocket.load_cert_chain('certs/ca.crt', keyfile='certs/ca.crt', password='henrik')
#sslsocket.set_ciphers('ECDH')
sslsocket.load_dh_params('certs/dhparams.pem')
sslsocket.wrap_socket(sock, do_handshake_on_connect=True, server_side=True)
sslsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#
sslsocket.bind((ip,port))
"""
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket = ssl.wrap_socket(sock,keyfile='certs/ca.key', certfile='certs/ca.crt', \
cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2, \
ciphers='ECDH', do_handshake_on_connect=True)
mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mySocket.bind((ip,port))

threads = []
socketListPort = []
socketList = []
activeUser = []


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
