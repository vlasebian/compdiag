import hashlib
import socket
import time
import selectors
from threading import Thread

from scapy.layers.inet import *
from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sendp
from scapy.supersocket import L3RawSocket

HOST = '127.0.0.1'  # Standard Loopback interface address (localhost)
PORT = 4432  # Port to listen on (non-privileged ports are > 1023)

#MIP = '192.168.1.73'
#MMAC = 'c8:ff:28:5d:79:cb'

class Reply:
    def __init__(self, interface, protocol, packet_capture):
        self.protocol = protocol
        self.interface = interface
        self.hashes = {}
        self.pkts = sniff(offline=packet_capture)

        conf.L3socket = L3RawSocket

        for pkt in self.pkts:
            if 'Raw' not in pkt:
                continue
            hashstr = hashlib.md5(pkt[Raw].command().encode()).hexdigest()
            if hashstr in self.hashes.keys():
                raise ValueError('Duplicate hash in packet dictionary.')
            self.hashes[hashstr] = pkt

    def handle_packet(self, pkt):
        # Check if packet contains any data, otherwise we cannot send a reply
        if 'Raw' not in pkt or pkt.sport == PORT:
            return

        hashstr = hashlib.md5(pkt[Raw].command().encode()).hexdigest()
        if hashstr not in self.hashes.keys():
            return

        reply_pkt = self.hashes[hashstr]

        # Craft new packet based on the old one
        new_pkt = IP(src=HOST, dst=pkt[IP].src)

        if UDP in pkt:
            if pkt[UDP].sport == PORT:
                return
            new_pkt /= UDP(sport=PORT, dport=pkt[UDP].sport)

        elif TCP in pkt:
            if pkt[TCP].sport == PORT:
                return

            new_pkt /= TCP(sport=PORT, dport=pkt[TCP].sport)
        else:
            raise ValueError('Protocol not supported.')

        new_pkt /= reply_pkt[Raw]

        # Send new packet
        new_pkt.show()
        send(new_pkt, iface=self.interface)

    def listen(self):
        # TODO: Move to another thread
        server_thread = ListeningThread()
        server_thread.start()
        sniff(iface=self.interface, filter=self.protocol, prn=self.handle_packet)
        server_thread.join()


class ListeningThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        sel = selectors.DefaultSelector()
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def accept(sock, mask):
            if sock == tcp_sock:
                conn, addr = sock.accept()
                conn.setblocking(False)
                sel.register(conn, selectors.EVENT_READ, read)

            if sock == udp_sock:
                try:
                    while True:
                        data, addr = udp_sock.recvfrom(1024)
                        #print(data.decode())
                except BlockingIOError:
                    return

        def read(conn, mask):
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    #print(data.decode())
            except BlockingIOError:
                pass
            finally:
                sel.unregister(conn)
                conn.close()

        try:
            udp_sock.bind((HOST, PORT))
            udp_sock.setblocking(False)
            sel.register(udp_sock, selectors.EVENT_READ, accept)

            tcp_sock.bind((HOST, PORT))
            tcp_sock.listen(100)
            tcp_sock.setblocking(False)
            sel.register(tcp_sock, selectors.EVENT_READ, accept)

            while True:
                events = sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
        except Exception:
            raise IOError('Socket error.')
        finally:
            udp_sock.close()
            tcp_sock.close()
            sel.close()
