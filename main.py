#!/usr/bin/env python3
import hashlib
import random
import socket
from bitarray import bitarray

# The server's hostname or IP address
HOST = 'p2psec.net.in.tum.de'
# The port used by the server
PORT = 13337
# Buffer size / Maximum package size
BUFFER_SIZE = 4096
# DHT Module
MODULE_CHOICE = 4963
# Team number
TEAM_NUMBER = 0
# Message type
ENROLL_REGISTER = 681


def get_header(size):
    return size.to_bytes(2, 'big') + ENROLL_REGISTER.to_bytes(2, 'big')


def encode_personal_infos():
    email = "m.grasso@tum.de\r\n".encode("UTF-8")
    firstname = "Marco\r\n".encode("UTF-8")
    lastname = "Grasso\r\n".encode("UTF-8")
    lrz_gitlab_username = "ga58len".encode("UTF-8")
    return email + firstname + lastname + lrz_gitlab_username


def build_registration_message(data):
    counter = 0
    while True:
        # nonce length is 64bit
        nonce = random.randbytes(8)

        # Challenge is everything after 4bytes/32bits
        challenge = data[4:]

        # Convert team number from into to bytes
        team_number = TEAM_NUMBER.to_bytes(2, 'big')

        # Convert module choice from into to bytes
        module_choice = MODULE_CHOICE.to_bytes(2, 'big')

        # Convert personal information strings into bytes with UTF-8
        personal_info = encode_personal_infos()

        # Concat challenge, team number, module, nonce and personal info
        registration_message = challenge
        registration_message += team_number
        registration_message += module_choice
        registration_message += nonce
        registration_message += personal_info

        # Compute sha256 wit padding according to RFC 6234
        registration_message = sha256_rfc6234_padding(registration_message)
        sha256 = hashlib.sha256(registration_message).digest()

        # If the resulting SHA256 value has the first 24 bits (3 bytes) set to 0 then you can register
        if int.from_bytes(sha256[:3], "big") == 0:
            print("Found valid sha256 result after " + str(counter) + " tries.")
            print("\n")
            return registration_message
        else:
            counter += 1
            if counter % 100000 == 0:
                print("Counter:", counter)
            if counter == 100000:
                # Test outputs
                print("challenge: ", challenge)
                print("len(challenge): ", len(challenge))
                print("team_number: ", team_number)
                print("len(team_number): ", len(team_number))
                print("module_choice: ", module_choice)
                print("len(module_choice): ", len(module_choice))
                print("nonce: ", nonce)
                print("len(nonce): ", len(nonce))
                print("personal_info: ", personal_info)
                print("len(personal_info): ", len(personal_info))
                print("\n")


def sha256_rfc6234_padding(msg):
    # RFC 6234: https://tools.ietf.org/html/rfc6234#section-4.1

    # Put the binary message into an BitArray
    b = bitarray()
    b.frombytes(msg)

    # Length of the message in bytes * 8 = length in bits
    length = len(msg * 8)

    # Append a 1 to the message
    b.append(1)

    # K 0s are appended where K is the smallest, non-negative solution to the equation ( length + 1 + K ) mod 512 = 448
    k = 0
    for k in range(0, 512):
        if (length + 1 + k) % 512 == 448:
            break

    for i in range(0, k):
        b.append(0)

    # Then append the 64-bit block that is length in binary representation.
    # After appending this block, the length of the message will be a
    # multiple of 512 bits.

    # Convert integer length of message to bitarray
    length_bits = bitarray()
    length_bits.frombytes(length.to_bytes(2, "big"))

    # Add leading zeros
    if len(length_bits) < 64:
        for i in range(0, 64 - len(length_bits)):
            b.append(0)

    # Append bits from the length bitarray
    for i in length_bits:
        b.append(i)

    ## Test
    ## Print result to console
    ## print("bitarray.hex():", b.tobytes().hex())
    ## print("bitarray.hex(): 61626364658000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028")
    ## print("\n")

    return b.tobytes()


# with as is Python's version of Java's try-with-resource statement
try:
    # Create client socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        # Connect to server
        server.connect((HOST, PORT))

        # Print success statement to console
        print("The socket has successfully connected to " + HOST + "\n")

        # Receive data from the server
        recv_data = server.recv(12)

        # Print received data
        print("Received data: ", recv_data)
        print("recv_data.hex(): ", recv_data.hex())
        print("recv_data length: ", len(recv_data))
        print("\n")

        ## Test
        ## print("sha256_rfc6234_padding: ",
              ## sha256_rfc6234_padding(
                  ## bytes([int("01100001", 2), int("01100010", 2), int("01100011", 2), int("01100100", 2),  int("01100101", 2)])))

        # # Build registration message
        # message = build_registration_message(recv_data)
        #
        # # Get header
        # header = get_header(len(message) + 4)
        # print("header: ", header)
        # print("len(header): ", len(header))
        #
        # registration_msg = header + message
        # print("registration_message: ", registration_msg)
        # print("registration_message.hex(): ", registration_msg.hex())
        # print("len(registration_message): ", len(registration_msg), "\n")
        #
        # # Send message to server
        # s.sendall(registration_msg)

        ## Test
        ## s.sendall(b"\x00\x84\x02\xa9\x11\x8b\n2\xa9\x13\x99Q\x00\x00\x13c>\xa7\xac\xb2\x04\xccm\x0bm.grasso@tum.de\r\nMarco\r\nGrasso\r\nga58len\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8")
        ## s.sendall(b"\x00\x84\x02\xa9\x14\xd6A\xfa\xfdOoY\x00\x00\x13c\xe7'\x9eal\xe0\x90\x0em.grasso@tum.de\r\nMarco\r\nGrasso\r\nga58len\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8")
        ## s.sendall(b"\x00\x84\x02\xa9\xd7\x81s\xed\xf4ng\xcd\x00\x00\x13c\x0e\x01i\xaf\t\x13\x83\xd4m.grasso@tum.de\r\nMarco\r\nGrasso\r\nga58len\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8")
        server.sendall(b"\x00\x84\x02\xa9\xea\xa0 \x99\xc7\xf9>x\x00\x00\x13c\xb7\xd1\xd7\x13_b\xbf\xd5m.grasso@tum.de\r\nMarco\r\nGrasso\r\nga58len\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8")

        # We are done sending from now on this socket only receives messages
        server.shutdown(1)

        # Receive data from the server
        recv_data_2 = server.recv(8)

        # Print received data
        print("recv_data_2: ", recv_data_2)
        print("recv_data_2.hex(): ", recv_data_2.hex())
        print("len(recv_data_2): ", len(recv_data_2))

        # We are done with both sending and receiving messages
        server.shutdown(2)
        print("END")
except socket.error as err:
    print("Error: %s" % err)
