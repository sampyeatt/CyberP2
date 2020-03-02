"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    John Pyeatt
    Margad Batamgalan
    Will Walker



"""

import socket
import cryptography
import os
import sys
import subprocess
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
from cryptography.fernet import Fernet

host = "localhost"
port = 10001
# iv = os.urandom(16)

# A helper function. It may come in handy when performing symmetric encryption


def pad_message(message):
    return message + b" " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    os.chdir(os.getcwd()+"/Project2/Project2/priv_ssh_dir")
    with open("id_rsa", "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            backend=default_backend(),
            password=None
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    original_message = private_key.decrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # print(original_message.decode())
    # print(original_message)
    original_message = original_message
    iv = original_message.rsplit(b"\x20", 1)[1]
    aes = original_message.rsplit(b"\x20", 1)[0]
    # print(iv)
    # print(aes)
    return Cipher(algorithms.AES(aes), modes.CBC(iv), backend=default_backend())


# Write a function that decrypts a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    # print("Message:", message, "IV", len(iv))
    encryptor = session_key.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return ct


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    # print("Length of decrypted", len(message))
    decryptor = session_key.decryptor()
    ct = decryptor.update(message) + decryptor.finalize()
    return ct

# def encrypt_message(message,session_key):
#     return session_key.encrypt(message)

# def decrypt_message(message, session_key):
#     return session_key.decrypt(message)
# Receive 1024 bytes from the client


def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                # hashed_password =
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)
                # print("Plaintext Key", plaintext_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                clientMes = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password

                print("Client message to be parsed", clientMes.decode())
                # TODO: parse the message
                username = clientMes.rsplit(" ", 1)[0]
                password = clientMes.rsplit(" ", 1)[1]
                ciphertext_message = verify_hash(username, password)
                # TODO: Encrypt response to client
                mess = encrypt_message(ciphertext_message, plaintext_key)
                send_message(sock, mess)

                # Send encrypted response
                # ciphertext_response = "testing"
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
