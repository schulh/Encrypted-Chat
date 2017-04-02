#!/usr/bin/env python3
import threading
import socket
import ssl
import argparse
from colors import bcolors
import time
import sys
import logging

class SSLServer(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        logging.info("New connection from " + str(conn))
        if args.verbosity == 1:
            print(bcolors.OKGREEN + "[+] New connection from " + str(conn) + bcolors.ENDC)

    def run(self):
        logging.info("created new thread")
        if args.verbosity == 1:
            print(bcolors.OKBLUE + "STARTED NEW THREAD" + bcolors.ENDC)
        user = self.conn.recv(buffer_size).decode()
        logging.info("User " + user + " entered the chatroom")
        activeUser.append(user)
        data = "[+] " + str(user) + " connected"
        self.broadcast(data, self.conn, self.addr, 0)
        welcomemsg = "Welcome " + user + "!\n" + "Active User: " + ",".join(activeUser)
        self.broadcast(welcomemsg, self.conn, self.addr, 1)
        while True:
            data = self.conn.recv(buffer_size).decode()
            logging.debug("received data from " + "'" + str(user) + "': " + str(data))
            if args.verbosity == 1:
                print(data)
            if data:
                data2 = str(data).split(" ")
                try:
                    if data2[1].startswith("/") == True:

                        if args.verbosity == 1:
                            print("[!] received command")
                        data2 = data2[1][1:]
                        # logging.info("received command '" + str(data2) + "' from " + str(user) )
                        command = self.serverCommands(str(data2))
                        command = "["+data2+"]" + " " + command
                        self.broadcast(command, self.conn, self.addr, 1)
                except IndexError as e:
                    if args.verbosity == 1:
                        print("Error: " + e)
                else:
                    self.broadcast(data, self.conn, self.addr, 0)
            else:
                if self.conn in socketList:
                    data = "[-] " + str(user) + "disconnected"
                    self.broadcast(data, self.conn, self.addr, 0)
                    socketList.remove(self.conn)
                    logging.info(user + " disconnected")
                    if args.verbosity == 1:
                        print(bcolors.FAIL + "[!] removed " + str(conn) + bcolors.ENDC)
                    self.conn.close()
                    self.isAlive = False
                    sys.exit()



    def serverCommands(self, command):
        if args.verbosity == 1:
            print("[CMD] " + command)
        if str(command) == 'help':
            helpmsg = "There is no help..."
            return helpmsg
        if str(command) == 'user':
            users = activeUser
            users = ",".join(users)
            return users
        else:
            return "not found"



    def broadcast(self, data, conn, addr, flag):
        #print(bcolors.OKGREEN + "SOCKET LIST: \n"  + bcolors.ENDC)
        #print(bcolors.OKGREEN + str(socketList) + bcolors.ENDC)
        if args.verbosity == 1:
            print("FLAG: " + str(flag))
        for i in range(0, len(socketList)):
            if socketListPort[i] != addr[1] and flag == 0:
                try:
                    socketList[i].send(data.encode())
                    logging.debug("Message sent to: " + str(socketListPort[i]))
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
                    logging.critical("Broken Pipe: " + str(conn))
                    conn.close()



parser = argparse.ArgumentParser()
parser.add_argument("--verbosity", "-v", action='count', help="increase output verbosity")
parser.add_argument("--ip", help="listening ip")
parser.add_argument("--port", help="listening port", type=int)
parser.add_argument("--logging", help="log output", type=str)
args = parser.parse_args()

if args.verbosity:
    print("verbosity turned on")
    print("LOG LEVEL: " + str(args.logging))
if args.ip:
    ip = args.ip
else:
    ip = '127.0.0.1'
if args.port:
    port = args.port
else:
    port = 50000

if args.logging:
    if args.logging == "info":
        args.logging = logging.INFO
    elif args.logging == "debug":
        args.logging = logging.DEBUG
    elif args.logging == "warning":
        args.logging = logging.WARNING
    elif args.logging == "critical":
        args.logging = logging.CRITICAL
else:
    args.logging = logging.INFO


logging.basicConfig(filename='/var/log/acidchat.log', level=args.logging, format='%(asctime)s:%(levelname)s: %(message)s')
buffer_size = 2048
logging.info("started server")


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
