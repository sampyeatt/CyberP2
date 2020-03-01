"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""

import socket
import os
import sys
import subprocess
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import Crypto.Cipher.AES as AES
import random
from cryptography.fernet import Fernet


PRIV_SSH_DIR = os.getcwd() + "/Project2/Project2/priv_ssh_dir"
host = "localhost"
port = 10001
cur_path = os.getcwd()
iv = os.urandom(16)


def key_present():
    if "id_rsa" in os.listdir(PRIV_SSH_DIR):
        return True
    else:
        return False
# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!


def pad_message(message):
    return message + " "*((16-len(message)) % 16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # print(os.getcwd())
    os.chdir(PRIV_SSH_DIR)
    if key_present():
        print("Key already exists")
        return os.urandom(32)
    else:
        #subprocess.call('ssh-keygen', shell=True)
        #subprocess.call(
        #    'ssh-keygen -f id_rsa -e -m pem > id_rsa.pem', shell=True)
        # subprocess.call('ssh-keygen -f id_rsa -e -m pem > id_rsa.pem', shell=True)
        key = Fernet.generate_key()
        f = Fernet(key)
        return f
        #return os.urandom(32)




# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    with open("id_rsa.pem", "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        encrypted = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    pass


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    print("Message:", message, "IV", len(iv))
    aes = AES.new(session_key, AES.MODE_CBC, iv)
    mess = pad_message(message)
    print("Length of message", len(mess))
    enc = aes.encrypt(mess)
    return enc


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    aes = AES.new(session_key, AES.MODE_CBC, iv)
    print("Length of decrypted", len(message))
    mess = pad_message(message.decode())
    mess = aes.decrypt(mess)
    return mess


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    # server_string = sock.recv(1024)
    # print(server_string)
    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        mess = encrypt_message(message, key)
        send_message(sock, mess)

        # TODO: Receive and decrypt response from server
        res = receive_message(sock)
        if(res == None):
            res = "Example"
        result = decrypt_message(res, key)
        print(result)
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
