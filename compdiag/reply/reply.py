import hashlib
from threading import Thread, Event

from scapy.layers.inet import *
from scapy.packet import Raw
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

BUFSIZ = 1024


class SniffingThread(Thread):
    def __init__(self, filename, interface, protocol):
        Thread.__init__(self)
        self.protocol = protocol
        self.interface = interface
        self.filename = filename[:filename.rfind('.')] + '_clone.pcapng'
        self.e = Event()

    def stop_sniffing(self):
        self.e.set()

    def run(self):
        capture = sniff(iface=self.interface,
                        filter=self.protocol,
                        stop_filter=lambda _: self.e.is_set())
        print('Writing result to', self.filename)
        capture = capture[0::2]
        wrpcap(self.filename, capture)


class Reply:
    def __init__(self, protocol, capture, server):
        self.raw_pkts = sniff(offline=capture)

        self.protocol = protocol
        self.server = server

        self.send_first = True
        self.first_pkts = []

        self.pkts = self.parse_packets()

    def update_entities(self, pkt):
        src = (pkt[IP].src, pkt[self.protocol].sport)
        dst = (pkt[IP].dst, pkt[self.protocol].dport)

        return src, dst

    def parse_packets(self):
        pkts = {}

        response_key = None
        server_data = None

        lastsrc, lastdst = None, None

        for i, pkt in enumerate(self.raw_pkts):
            if Raw not in pkt:
                continue

            src, dst = self.update_entities(pkt)

            if src == self.server:
                # Handle message sent by the server

                # If a server message is encountered, client cannot
                if self.send_first: self.send_first = False

                # A message sent by the server after a client message resets
                # the key. A new response will be created.
                if lastsrc != src:
                    response_key = None

                if server_data is None:
                    server_data = hashlib.md5(bytearray(pkt[Raw].load)).hexdigest()
                else:
                    # Succesive server messages.
                    server_data += hashlib.md5(bytearray(pkt[Raw].load)).hexdigest()

            else:
                #### Handle message sent by the client

                # First message is sent by the client
                if self.send_first:
                    self.first_pkts.append(pkt[Raw].load)
                    continue

                # Message sent by client after another client message: append to
                # the entry another message to be sent.
                if lastsrc == src and response_key is not None:
                    pkts[response_key].append(pkt[Raw].load)
                    continue

                # Message sent by client after a server message: create a new
                # entry in the dictionary having as key the hash of the data
                # sent by the server:

                if server_data is not None:
                    response_key = server_data
                    pkts[response_key] = [pkt[Raw].load]

                server_data = None

            lastsrc, lastdst = src, dst

        return pkts

    def reply(self):

        if self.protocol == TCP:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.server)

        elif self.protocol == UDP:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Timeout in case of multiple messages are being sent from the server.
        composed_response_hash = None
        while True:
            if self.first_pkts:
                for res in self.first_pkts:
                    if self.protocol == TCP:
                        sock.send(res)
                    elif self.protocol == UDP:
                        sock.sendto(res, self.server)

                self.first_pkts = []

            try:
                if self.protocol == TCP:
                    data = sock.recv(BUFSIZ)
                elif self.protocol == UDP:
                    data = sock.recvfrom(BUFSIZ)
                    data = data[0]
            except KeyboardInterrupt:
                break

            if not data:
                break

            # Search direct answer
            response_hash = hashlib.md5(data).hexdigest()
            if response_hash in self.pkts:
                for res in self.pkts[response_hash]:
                    if self.protocol == TCP:
                        sock.send(res)
                    elif self.protocol == UDP:
                        sock.sendto(res, self.server)
                composed_response_hash = None
                continue

            # Save response for later composed answer search
            if composed_response_hash is None:
                composed_response_hash = response_hash
            else:
                composed_response_hash += response_hash

            # Search for composed answer
            if composed_response_hash in self.pkts:
                for res in self.pkts[composed_response_hash]:
                    if self.protocol == TCP:
                        sock.send(res)
                    elif self.protocol == UDP:
                        sock.sendto(res, self.server)
                composed_response_hash = None
                continue

            # Check if message can be continued with another known messages.
            # If not, do not keep track of it.
            keep_track = False
            for key in self.pkts.keys():
                if key.startswith(composed_response_hash):
                    keep_track = True
                    break

            if not keep_track and composed_response_hash == response_hash:
                composed_response_hash = None
                continue
            else:
                for key in self.pkts.keys():
                    if key.startswith(response_hash):
                        keep_track = True
                        composed_response_hash = response_hash
                        break

        sock.close()


def reply(protocolstr, capture, iface, host, port):
    if protocolstr.lower() == 'tcp':
        protocol = TCP
    elif protocolstr.lower() == 'udp':
        protocol = UDP
    else:
        raise ValueError('Protocol not supported')

    if host == 'localhost': host = '127.0.0.1'
    server = (host, int(port))

    print('Replying packet capture', capture, '...')

    sniff_thread = SniffingThread(capture, iface, protocolstr)
    sniff_thread.start()

    # Wait two seconds for sniffing to begin.
    time.sleep(2)

    Reply(protocol, capture, server).reply()

    sniff_thread.stop_sniffing()
    sniff_thread.join()
