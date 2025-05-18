import socket
import json
import time

username = input("Enter a name:")
IP = socket.gethostbyname(socket.gethostname())

PORT = 6000
BROADCAST_IP = "192.168.1.255"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

sock.bind(("", PORT))
peers_file = "peers.json"
try:
    with open(peers_file, "r") as f:
        peers = json.load(f);
        f.close()
except:
    pass

while True:
    data, addr = sock.recvfrom(1024)
    msg = json.dumps({"username": username, "ip": IP})
    sock.sendto(msg.encode(), (BROADCAST_IP, PORT))
    print(msg)
    time.sleep(2)
    try:
        msg = json.loads(data.decode())
        username = msg["username"]
        ip = addr[0]
        peers[ip] = {"username": username, "last_seen": time.time()}
        with open(peers_file, "w") as f:
            json.dump(peers, f)
            f.close()
        
        print(f"[+] {username} is online ({ip})")
    except:
        print("fuck")
        continue

    
