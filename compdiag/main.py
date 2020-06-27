import json
import argparse
import pyshark

from compdiag.diagram.basediagram import recreate_diagram
from compdiag.diagram.state import State
from compdiag.diagram.tcp.tcpstate import TCPStateDiagram
from compdiag.diagram.transition import Transition
from compdiag.diagram.udp.udpstate import UDPStateDiagram
from compdiag.diagram.dns.dnsstate import DNSStateDiagram
from compdiag.diagram.http.httpstate import HTTPStateDiagram
from compdiag.diagram.http2.http2state import HTTP2StateDiagram
from compdiag.diagram.ble.blestate import BLEStateDiagram
from compdiag.reply.reply import Reply


class Compdiag:

    def __init__(self):
        pass

    @staticmethod
    def reply(protocol, filename, iface):
        # TODO: launch a second thread that captures packets, then generate diagram from result packet capture
        Reply(iface, protocol, filename).listen()

    @staticmethod
    def pkt_parser(file, display_filter=None):
        if display_filter is not None:
            return pyshark.FileCapture(file, display_filter=display_filter)
        return pyshark.FileCapture(file)

    @staticmethod
    def build_diagram(file, protocol, output_filename=None, display_filter=None):
        pkts = Compdiag.pkt_parser(file, display_filter)

        if not output_filename:
            output_filename = protocol + 'diag'

        if protocol == 'tcp':
            TCPStateDiagram().create_diagram(pkts, output_filename)

        elif protocol == 'udp':
            UDPStateDiagram().create_diagram(pkts, output_filename)

        elif protocol == 'dns':
            DNSStateDiagram().create_diagram(pkts, output_filename)

        elif protocol == 'http':
            HTTPStateDiagram().create_diagram(pkts, output_filename)

        elif protocol == 'http2':
            HTTP2StateDiagram().create_diagram(pkts, output_filename)

        elif protocol == 'ble':
            BLEStateDiagram().create_diagram(pkts, output_filename)

        else:
            raise NotImplementedError()

        pkts.close()
        State.reset_idx()
        Transition.reset_idx()

    @staticmethod
    def rebuild_diagram(file, modifier=None, output_filename='reconsdiag'):
        raw_data = open(file, 'r').read()

        data = json.loads(raw_data)
        recreate_diagram(data, modifier, output_filename)

    @staticmethod
    def cli():
        arg_parser = argparse.ArgumentParser(description='Packet capture analysis framework.')

        arg_parser.add_argument(
            '--filter', metavar='filter', type=str,
            help='Display filter used on captures when parsing the file, same format as tshark.')
        arg_parser.add_argument(
            '--reply', metavar='reply', type=bool, default=False,
            help='Use the packet capture to build replies, and listen for incoming packets.')
        arg_parser.add_argument(
            '--iface', metavar='iface', type=str, default='lo',
            help='Interface where replies are sent. To be used only with --reply option.')
        arg_parser.add_argument(
            'protocol', metavar='protocol', type=str,
            help='Protocol used in the given capture file.',
            choices=['ble', 'tcp', 'udp', 'dns', 'http', 'http2'])
        arg_parser.add_argument(
            'file', metavar='capture_file', type=str,
            help='Pcap or PcapNg file containing packet captures.')

        args = arg_parser.parse_args()
        # TODO: add the other options too
        if args.reply:
            Compdiag.reply(args.protocol, args.file, args.iface)
        else:
            # TODO: add interface parameter
            Compdiag.build_diagram(args.file, args.protocol)


if __name__ == '__main__':
    Compdiag.cli()
