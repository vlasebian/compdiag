import os

from compdiag.main import Compdiag
from compdiag.diagram.basediagram import Reconstruct
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

HUE_BLE_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/hue-ble/'
DS4_BLE_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/ds4-ble/'
DS4_HTTP2_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/ds4-http2/'
UDP_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/udp/'
TCP_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/tcp/'
DNS_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/dns/'
HTTP_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/http/'
HTTP2_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/http2/'

DIRECTORIES = [
        #HUE_BLE_PCAP_DIR,
        #DS4_BLE_PCAP_DIR,
        #DS4_HTTP2_PCAP_DIR,
        #UDP_PCAP_DIR,
        #TCP_PCAP_DIR,
        #DNS_PCAP_DIR,
        HTTP_PCAP_DIR,
        #HTTP2_PCAP_DIR,
    ]


def reconstruct_modifier(states, transitions):
    states, transitions = Reconstruct.remove_states(range(17,19), states, transitions)
    transitions.append(Transition('16', '20', None, Reconstruct.ARR_DOWN))
    transitions.append(Transition('15', '19', None, Reconstruct.ARR_DOWN))
    states, transitions = Reconstruct.unify_states(5, [8], states, transitions)
    states, transitions = Reconstruct.unify_states(6, [7], states, transitions)
    return states, transitions


def reconstruct_test():
    Compdiag.rebuild_diagram('dnsdiag.json', reconstruct_modifier, 'reconsdiag')

def main():
    for dirr in DIRECTORIES:
        protocol = None

        for ptcl in ['ble', 'udp', 'tcp', 'dns', 'http', 'http2']:
            if ptcl in dirr:
                protocol = ptcl
        if not protocol:
            raise ValueError('Protocol not found')

        for filename in os.listdir(dirr):
            if 'btsmp' in filename:
                continue

            if (filename.endswith('.png') or
               filename.endswith('.json')):
                continue

            print('**** Generating diagram from ' + dirr + filename + '...')
            Compdiag.build_diagram(dirr + filename, protocol, dirr + filename)



if __name__ == '__main__':
    main()
    #reconstruct_test()

