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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
from cryptography.fernet import Fernet


PRIV_SSH_DIR = os.getcwd() + "/Project2/Project2/priv_ssh_dir"
host = "localhost"
port = 10001
# Initialization Vector for AES generation
iv = os.urandom(16)
# Random bytes for AES generation
s_key = os.urandom(16)


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
    os.chdir(PRIV_SSH_DIR)
    if key_present():
        print("Key already exists")
        # generating random AES key with initialization vector iv
        return Cipher(algorithms.AES(s_key), modes.CBC(iv), backend=default_backend())
    else:
        # generate private/public key pair
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537,
                                       key_size=1024)

        # get public key in OpenSSH format
        public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH)

        # get private key in PEM container format
        pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())
        # decode to printable strings
        private_key_str = pem.decode('utf-8')
        public_key_str = public_key.decode('utf-8')
        # Writing private key to file
        f = open("id_rsa", "wb+")
        f.write(pem)
        f.close()
        # Writing the public key to file
        f = open("id_rsa.pem", "wb+")
        f.write(public_key)
        f.close()
        # generating random AES key with initialization vector iv
        return Cipher(algorithms.AES(s_key), modes.CBC(iv), backend=default_backend())


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    # Open public key file
    with open("id_rsa.pem", "rb") as file:
        # Loading public key
        public_key = serialization.load_ssh_public_key(
            file.read(),
            backend=default_backend()
        )
        # Encrypting session key and initialization vector to send to server
        encrypted = public_key.encrypt(
            s_key + b"\x20" + iv,
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
    encryptor = session_key.encryptor()
    # Padding message for AES encryption
    mess = pad_message(message)
    ct = encryptor.update(mess.encode()) + encryptor.finalize()
    return ct


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    decryptor = session_key.decryptor()
    ct = decryptor.update(message) + decryptor.finalize()
    return ct

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
        result = decrypt_message(res, key)
        print(result.decode())
        if(result.decode() == "True"):
            print("User successfully authenticated!")
        else:
            print("Password or username incorrect")
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
