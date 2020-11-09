from compdiag.diagram.basediagram import Diagram, save_diagram_data, generate_diagram
from compdiag.diagram.state import State
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.transition import Transition
from compdiag.uml.statediagram import UMLStateDiagram


class HTTPStateDiagram(Diagram):
    def create_diagram(self, pkts, output_filename):
        init_state = State('START', None, None)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        for i, pkt in enumerate(pkts):
            if 'http' not in pkt:
                continue

            self.update_entities(pkt)

            # Save entity if it does not exist
            if self.src not in self.trx.keys():
                self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(init_state)

            if self.dst not in self.trx.keys():
                self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(init_state)

            operation = None
            transition = ''

            if 'request' in pkt.http.field_names:
                operation = pkt.http.request_method
                transition += pkt.http.request_method + ' Request to ' + pkt.http.host

            elif 'response' in pkt.http.field_names:
                operation = 'Response'
                transition += pkt.http.response_code + ' ' + pkt.http.response_code_desc

            else:
                pkt.pretty_print()
                raise ValueError('HTTP packet is neither request or response.')

            payload = str(pkt.http)

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                data_sent = State(self.src, operation + ' sent', payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                data_recv = State(self.dst, operation + ' received', payload)
                self.trx[self.dst].states.append(data_recv)

            # Add transitions between states
            self.transitions.append(Transition(last_src_state.idx,
                                               data_sent.idx,
                                               None,
                                               UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(last_dst_state.idx,
                                               data_recv.idx,
                                               None,
                                               UMLStateDiagram.ARROW_DIR_DOWN))

            # Add message arrow
            self.transitions.append(Transition(data_sent.idx,
                                               data_recv.idx,
                                               transition,
                                               self.trx[self.src].arrow))

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(
                Transition(self.trx[self.src].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(
                Transition(self.trx[self.dst].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        save_diagram_data(states, self.transitions, output_filename)
        generate_diagram(states, self.transitions, output_filename)
