from compdiag.diagram.basediagram import Diagram
from compdiag.diagram.state import State
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.transition import Transition
from compdiag.uml.statediagram import UMLStateDiagram


class HTTP2StateDiagram(Diagram):
    def update_entities(self, pkt):
        if 'exported_pdu' in pkt:
            self.src, self.dst = (
                pkt.exported_pdu.ip_src + ':' + pkt.exported_pdu.src_port,
                pkt.exported_pdu.ip_dst + ':' + pkt.exported_pdu.dst_port
            )
        else:
            self.src, self.dst = (
                pkt.ip.src + ':' + pkt.tcp.srcport,
                pkt.ip.dst + ':' + pkt.tcp.dstport
            )

    def create_diagram(self, pkts, output_filename):
        init_state = State('START', None, None)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        for i, pkt in enumerate(pkts):
            if 'http2' not in pkt:
                continue

            self.update_entities(pkt)

            # Save entity if it does not exist
            if self.src not in self.trx.keys():
                self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(init_state)

            if self.dst not in self.trx.keys():
                self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(init_state)

            if 'type' not in pkt.http2.field_names:
                # magic packet
                continue

            pkt_type = pkt.http2.type

            if pkt_type == '0':
                transition = 'DATA'

            elif pkt_type == '1':
                transition = 'HEADERS'

                if 'headers_method' in pkt.http2.field_names:
                    transition += ' ' + pkt.http2.headers_method

                if 'headers_path' in pkt.http2.field_names:
                    transition += ' ' + pkt.http2.headers_path

                if 'headers_status' in pkt.http2.field_names:
                    transition += ' ' + pkt.http2.headers_status

            elif pkt_type == '2':
                transition = 'PRIORITY'

            elif pkt_type == '3':
                transition = 'RST_STREAM'

            elif pkt_type == '4':
                transition = 'SETTINGS'

            elif pkt_type == '5':
                transition = 'PUSH_PROMISE'

            elif pkt_type == '6':
                transition = 'PING'

            elif pkt_type == '7':
                transition = 'GOAWAY'

            elif pkt_type == '8':
                transition = 'WINDOW UPDATE'

            elif pkt_type == '9':
                transition = 'CONTINUATION'

            else:
                transition = 'ERROR'
                pkt.pretty_print()
                # raise ValueError('HTTP2 packet type not recognized')

            payload = str(pkt.http2)

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                data_sent = State(self.src, None, payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                data_recv = State(self.dst, None, payload)
                self.trx[self.dst].states.append(data_recv)

            # Add transitions between states
            self.transitions.append(Transition(last_src_state.idx,
                                               data_sent.idx,
                                               str(i),
                                               UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(last_dst_state.idx,
                                               data_recv.idx,
                                               str(i),
                                               UMLStateDiagram.ARROW_DIR_DOWN))

            # Add message arrow
            self.transitions.append(Transition(data_sent.idx,
                                               data_recv.idx,
                                               transition,
                                               self.trx[self.src].arrow))

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(
                Transition(self.trx[self.src].states[-1].idx, None, str(i), UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(
                Transition(self.trx[self.dst].states[-1].idx, None, str(i), UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        save_diagram_data(states, self.transitions, output_filename)
        generate_diagram(states, self.transitions, output_filename)
