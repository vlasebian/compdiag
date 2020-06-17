import json
import pyshark
import argparse

from compdiag.diagram.tcp.tcpstate import TCPStateDiagram
# from compdiag.diagram.dns.dnsstate import DNSStateDiagram
from compdiag.diagram.udp.udpstate import UDPStateDiagram
# from compdiag.diagram.http.httpstate import HTTPStateDiagram
# from compdiag.diagram.http.http2state import HTTP2StateDiagram

# from compdiag.diagram.ble.blestate import BLEStateDiagram

class PacketAnalyser():

    @staticmethod
    def pkt_parser(file, display_filter=None):
        if display_filter is not None:
            return pyshark.FileCapture(file, display_filter=display_filter)
        return pyshark.FileCapture(file)

    @staticmethod
    def build_diagram(file, protocol, diagtype='state', display_filter=None):
        pkts = PacketAnalyser.pkt_parser(file, display_filter)

        if protocol == 'tcp':
            if diagtype == 'state':
                TCPStateDiagram().create_diagram(pkts, output_filename='tcpdiag')

        # elif protocol == 'ble':
        #     if diagtype == 'state':
        #         BLEStateDiagram().create_diagram(pkts)

        elif protocol == 'udp':
            if diagtype == 'state':
                UDPStateDiagram().create_diagram(pkts, output_filename='udpdiag')

        # elif protocol == 'dns':
        #     if diagtype == 'state':
        #         DNSStateDiagram().create_diagram(pkts)

        # elif protocol == 'http':
        #     if diagtype == 'state':
        #         HTTPStateDiagram().create_diagram(pkts)

        # elif protocol == 'http2':
        #     if diagtype == 'state':
        #         HTTP2StateDiagram().create_diagram(pkts)
        else:
            raise NotImplementedError()

    @staticmethod
    def rebuild_diagram(file, protocol, type='state', modifier=None, output_filename='reconsdiag'):
        raw_data = open(file, 'r')
        data = json.loads(raw_data)

        if type == 'state':
            if protocol == 'tcp':
                TCPStateDiagram().recreate_diagram(data, modifier, output_filename)
                return

        else:
            raise NotImplementedError()

    @staticmethod
    def cli():
        arg_parser = argparse.ArgumentParser(description='Packet capture analysis framework.')

        arg_parser.add_argument(
                '--diagram_type', metavar='type', type=str,
                help='type of diagram to be generated from capture file, default is state diagram',
                default= 'state',
                choices=['state', 'sequence'])
        arg_parser.add_argument(
                '--filter', metavar='filter', type=str,
                help='display filter used on captures when parsing the file, same format as tshark')
        arg_parser.add_argument(
                'protocol', metavar='protocol', type=str,
                help='transmission protocol used in the given capture file',
                choices=['ble', 'tcp', 'udp', 'dns', 'http', 'http2'])
        arg_parser.add_argument(
                'file', metavar='capture_file', type=str,
                help='pcap or pcapng file containing packet captures')

        args = arg_parser.parse_args()

        # TODO: add the other option too
        PacketAnalyser.build_diagram(args.file, args.protocol)


if __name__ == '__main__':
    PacketAnalyser.cli()