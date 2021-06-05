#!/usr/bin/env python3

import socket
import random
import hashlib
import sys
import threading
import time
from bitarray import bitarray

TEAM_NUMBER = 0
MODULE_CHOICE = 4963

HOST = "p2psec.net.in.tum.de"
PORT = 13337
ENROLL_REGISTER = 681

class Register:

    data = b''

    def main(self):
        # get data from server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.connect((HOST, PORT))
            # serverfile = server.makefile('rwb')
            # self.data = serverfile.read(12)
            self.data = server.recv(12)
            # t = threading.Thread(target=listen_for_messages,args=(server,))
            # t.daemon = True
            # t.start()
            # time.sleep(1)
            print([hex(x) for x in self.data])
            packet = build_message(self.data[4:])
            self.data = b''
            print("the packet send ready: ", packet)
            # packet_size = int.from_bytes(packet[:2],byteorder='big')
            # serverfile.write(packet)
            # serverfile.flush()

            back = server.send(packet)
            print("sent packet", back)
            # time.sleep(1)
            # self.data = serverfile.read(12)
            print("before receive",self.data)
            self.data = server.recv(1024)

            # try:
            #     self.data = server.recv(1024,socket.MSG_DONTWAIT|socket.MSG_PEEK)
            # except Exception:
            #     print("eep",sys.exc_info()[0])
            print("received data: ", self.data)
            print([hex(x) for x in self.data])
            message = self.data[2:4]
            team_number = self.data[6:8]
            error_description = self.data[8:]
            print("status", message)
            print("error/team-number", team_number)
            print("error/team-number", int.from_bytes(team_number,"little"))
            print("error/team-number", int.from_bytes(team_number,"big"))
            print("error description", error_description)
            print("the hash is", hashlib.sha256(packet[4:]).digest())

    def listen_for_messages(self,server):
        run = 0
        print("start thread with socket", server)
        self.data = b''
        while True:
            message = server.recv(1024)
            old_data = self.data
            self.data += message
            if(old_data != self.data):
                print("message received from thread: ",self.data)
            # print(f'run number: {run}')
            run += 1

def build_message(challenge):
    message = proof_of_work(challenge, get_choice_message(), get_info_message())
    # message = challenge +  get_choice_message() + random.randbytes(8)+  get_info_message()
    header = get_header(len(message))
    return header + message

def proof_of_work(challenge,choosing_part,info_part):
    run = 0
    while True:
        nonce = random.randbytes(8)
        message = challenge + choosing_part + nonce + info_part
        # message = pad_for_sha256(message)
        sha = hashlib.sha256(message).digest()
        # sha = b'\x00\x00\x00'
        # print(f'run number: {run}',end='\r')
        if(sha[:3] == b'\x00\x00\x00'):
            print(len(message))
            return message
        run += 1

def pad_for_sha256(message):
    m_as_bits = bitarray()
    m_as_bits.frombytes(message)
    m_as_bits.append(1)
    m_as_bits.extend(calculate_K_padding(message) * '0')
    size = bytes.fromhex(str.format('{:016X}',len(message)))
    m_as_bits.frombytes(size)
    return m_as_bits.tobytes()

def calculate_K_padding(message):
    return  (512 - (len(message) * 8 + 1 + 64)) % 512

def get_choice_message():
    team_number = bytes.fromhex(str.format('{:04X}',TEAM_NUMBER))
    project_choice = bytes.fromhex(str.format('{:04X}',MODULE_CHOICE))
    return team_number + project_choice

def get_info_message():
    email = "s.walchshaeusl@tum.de\r\n".encode()
    firstname = "Sebastian\r\n".encode()
    lastname = "Walchshaeusl\r\n".encode()
    lrz_gitlab_username = "ga84mim".encode()
    return email + firstname + lastname + lrz_gitlab_username

def get_header(size):
    size = bytes.fromhex(str.format('{:04X}',size + 4))
    enroll_register=bytes.fromhex(str.format('{:04X}',ENROLL_REGISTER))
    return size + enroll_register

    # def mysend(server,msg,MSGLEN):
    #     totalsent = 0
    #     while totalsent < MSGLEN:
    #         sent = server.send(msg[totalsent:])
    #         if sent == 0:
    #             raise RuntimeError("socket connection broken")
    #         totalsent = totalsent + sent

    # def myreceive(server,MSGLEN):
    #     chunks = []
    #     bytes_recd = 0
    #     while bytes_recd < MSGLEN:
    #         chunk = server.recv(min(MSGLEN - bytes_recd, 2048))
    #         if chunk == b'':
    #             raise RuntimeError("socket connection broken")
    #         chunks.append(chunk)
    #         bytes_recd = bytes_recd + len(chunk)
    #         return b''.join(chunks)


if __name__ == "__main__":
    program = Register()
    program.main()
