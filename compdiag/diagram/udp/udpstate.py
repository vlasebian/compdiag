import json

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.basediagram import Diagram, generate_diagram, save_diagram_data

from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

class UDPStateDiagram(Diagram):
    def create_diagram(self, pkts, output_filename):

        init_state = State('START', None, None)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        for i, pkt in enumerate(pkts):
            if 'ip' not in pkt or 'udp' not in pkt:
                continue

            self.update_entities(pkt)

            if (self.trx and 
                    (self.src not in self.trx.keys() or
                     self.dst not in self.trx.keys())):
                continue
            
            # Save entity if it does not exist
            if self.src not in self.trx.keys():
                self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(init_state)
            
            if self.dst not in self.trx.keys():
                self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(init_state)

            # FIXME: Sometimes upper layer data is not extracted
            # Check for data or higher layer
            if 'data' in pkt:
                # Raw UDP, no higher protocol
                payload = pkt.data.data
            else:
                # Higher protocol present
                highest_layer = pkt.highest_layer.lower()
                payload = str(pkt[highest_layer])

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                data_sent = State(self.src, 'DATA sent', payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                data_recv = State(self.dst, 'DATA recv', payload)
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
                                               payload if len(payload) < 10 else payload[:10] + '...',
                                               self.trx[self.src].arrow))

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(Transition(self.trx[self.src].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(self.trx[self.dst].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        save_diagram_data(states, self.transitions, output_filename)
        generate_diagram(states, self.transitions, output_filename)
