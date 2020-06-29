import sys
import socket
import selectors

from threading import Thread

from scapy.packet import Raw
from scapy.sendrecv import sniff
from scapy.layers.inet import *

BUFSIZ = 1024

class ReplyThread(Thread):
    def __init__(self, protocol, capture, host, port):
        Thread.__init__(self)
        self.pkts = sniff(offline=sys.argv[2])
        self.protocol = protocol
        self.server = (host, int(port))

    def run(self):
        if self.protocol == 'tcp':
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.server)

            for pkt in self.pkts:
                # Ignore connection packets
                if Raw not in pkt:
                    continue

                sock.send(pkt[Raw].load)
                # Wait for response

                data = sock.recv(BUFSIZ)
                print(data)
            sock.close()

        elif self.protocol == 'udp':
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            for pkt in self.pkts:
                # Ignore connection packets
                if Raw not in pkt:
                    continue

                sock.sendto(pkt[Raw].load, self.server)
                # Wait for response

                data = sock.recvfrom(BUFSIZ)
                print(data)

            sock.close()
        else:
            raise ValueError('Protocol not supported')


def main():
    protocol = sys.argv[1]
    capture  = sys.argv[2]
    host     = sys.argv[3]
    port     = sys.argv[4]

    print('Replying packet capture', sys.argv[2], '...')
    reply_thread = ReplyThread(protocol, capture, host, port)
    reply_thread.start()
    #sniff(iface='lo', filter=protocol)
    reply_thread.join()

if __name__ == '__main__':
    main()
