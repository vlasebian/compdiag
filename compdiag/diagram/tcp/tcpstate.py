import json

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition


class TCPTransciever(Transciever):
    def __init__(self, idx, arrow_direction):
        super().__init__(idx, arrow_direction)
        self.fin_sent   = False
        self.fin_recv   = False


class TCPState(State):
    def __init__(self, name, info, data, flags, seq, ack, idx=None):
        super().__init__(name, info, data, idx)

        self.flags = flags
        self.seq = seq 
        self.ack = ack

    def get_info(self):
        info = super().get_info()
        info += '\\nseq: ' + self.seq
        info += '\\nack: ' + self.ack
        info += '\\nflags: ' + ' '.join(self.flags)

        return info
    
    def has_flags(self, flags):
        for flag in flags:
            if flag not in self.flags:
                return False
        return True
        
    def get_dict(self):
        return {
            'idx':   self.idx,
            'name':  self.name,
            'info':  self.info,
            'data':  self.data,
            'flags': self.flags,
            'seq':   self.seq,
            'ack':   self.ack,
        }


class TCPStateDiagram():
    def __init__(self):
        self.trx = {}
        self.transitions = []

        self.src = None
        self.dst = None

    def update_entities(self, packet):
        self.src, self.dst = (
            packet.ip.src + ':' + packet.tcp.srcport,
            packet.ip.dst + ':' + packet.tcp.dstport
        )

    def add_standard_transition(self, new_src_state, new_dst_state, operation, i, check_states=False):
        last_src_state = self.trx[self.src].states[-1]
        last_dst_state = self.trx[self.dst].states[-1]

        # Add transitions between states
        self.transitions.append(Transition(last_src_state.idx, new_src_state.idx, str(i), UMLStateDiagram.ARROW_DIR_DOWN))
        self.transitions.append(Transition(last_dst_state.idx, new_dst_state.idx, str(i), UMLStateDiagram.ARROW_DIR_DOWN))

        # Add message arrow
        self.transitions.append(Transition(new_src_state.idx, new_dst_state.idx, operation, self.trx[self.src].arrow))

        if check_states:
            if self.trx[self.src].get_state(new_src_state.data) is None and not new_src_state is None:
                self.trx[self.src].states.append(new_src_state)
            if self.trx[self.dst].get_state(new_dst_state.data) is None and not new_dst_state is None:
                self.trx[self.dst].states.append(new_dst_state)
        else:
            self.trx[self.src].states.append(new_src_state)
            self.trx[self.dst].states.append(new_dst_state)

    def get_flags(self, packet):
        flags = []

        if ('flags_syn' in packet.tcp.field_names and
            packet.tcp.flags_syn.int_value == 1):
            flags.append('SYN')

        if ('flags_ack' in packet.tcp.field_names and
            packet.tcp.flags_ack.int_value == 1):
            flags.append('ACK')

        if ('flags_fin' in packet.tcp.field_names and
            packet.tcp.flags_fin.int_value == 1):
            flags.append('FIN')

        if ('flags_push' in packet.tcp.field_names and
            packet.tcp.flags_push.int_value == 1):
            flags.append('PSH')

        if ('flags_rst' in packet.tcp.field_names and
            packet.tcp.flags_rst.int_value == 1):
            flags.append('RST')

        return flags

    def create_diagram(self, pkts, output_filename='tcpstate'):
        closed_state = State('CLOSED', None, None)
        self.transitions.append(Transition(None, closed_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        for i, pkt in enumerate(pkts):
            if 'ip' not in pkt or 'tcp' not in pkt:
                continue

            self.update_entities(pkt)
            flags = self.get_flags(pkt)

            if (self.trx and 
                    (self.src not in self.trx.keys() or
                     self.dst not in self.trx.keys())):
                continue

            if 'SYN' in flags and not 'ACK' in flags:
                # SYN - connection opening requested
                self.trx[self.src] = TCPTransciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(closed_state)

                self.trx[self.dst] = TCPTransciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(closed_state)

                new_src_state = TCPState(self.src, 'SYN sent', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                new_dst_state = TCPState(self.dst, 'SYN recv', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)

                self.add_standard_transition(new_src_state, new_dst_state, 'SYN', i)

                continue
            elif 'SYN' in flags and 'ACK' in flags:
                # SYN ACK - half-open connection

                syn_ack_sent = TCPState(self.src, 'SYN ACK sent', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                syn_ack_recv = TCPState(self.dst, 'SYN ACK recv', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)

                self.add_standard_transition(syn_ack_sent, syn_ack_recv, 'SYN ACK', i)

                continue

            elif 'ACK' in flags and int(pkt.tcp.len) != 0:
                # application data
                payload = pkt.tcp.payload

                data_sent = self.trx[self.src].get_state(payload)
                if data_sent is None:
                    data_sent = TCPState(self.src, 'DATA sent', payload, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)

                data_recv = self.trx[self.dst].get_state(payload)
                if data_recv is None:
                    data_recv = TCPState(self.dst, 'DATA recv', payload, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)

                self.add_standard_transition(data_sent, data_recv, 'App data', i, True)

                continue

            elif 'FIN' in flags and 'ACK' in flags:
                # FIN ACK - connection closing requested

                fin_sent = TCPState(self.src, 'FIN sent', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                fin_recv = TCPState(self.dst, 'FIN recv', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)

                self.add_standard_transition(fin_sent, fin_recv, 'App data', i)

                self.trx[self.src].fin_sent = True
                self.trx[self.dst].fin_recv = True

                continue

            elif 'ACK' in flags:
                # ACK connection established
                if (self.trx[self.src].states[-1].has_flags(['SYN', 'ACK']) and
                    self.trx[self.dst].states[-1].has_flags(['SYN', 'ACK'])):

                    ack_sent = TCPState(self.src, 'ACK sent', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                    ack_recv = TCPState(self.dst, 'ACK recv', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                    self.add_standard_transition(ack_sent, ack_recv, 'ACK', i)

                    established_state = State('ESTABLISHED', None, None)

                    self.transitions.append(Transition(self.trx[self.src].states[-1].idx, established_state.idx, str(i), UMLStateDiagram.ARROW_DIR_DOWN))
                    self.transitions.append(Transition(self.trx[self.dst].states[-1].idx, established_state.idx, str(i), UMLStateDiagram.ARROW_DIR_DOWN))

                    self.trx[self.src].states.append(established_state)
                    self.trx[self.dst].states.append(established_state)

                    continue

                # Simple ACK, shown only if requested explicitly.
                elif False:
                    # FIXME: ACK message received
                    ack_sent = TCPState(self.src, 'ACK sent', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                    ack_recv = TCPState(self.dst, 'ACK recv', None, flags, pkt.tcp.seq_raw, pkt.tcp.ack_raw)
                    self.add_standard_transition(ack_sent, ack_recv, 'ACK', i)
                    continue
            else:
                pkt.tcp.pretty_print()
                # TODO: handle RST packets
                raise ValueError('Unrecognized TCP packet type.')

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(Transition(self.trx[self.src].states[-1].idx, None, str(i), UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(self.trx[self.dst].states[-1].idx, None, str(i), UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        diagram_data = {
            'states':      [state.get_dict() for state in states],
            'transitions': [tr.get_dict() for tr in self.transitions],
        }

        with open(output_filename + '.json', 'w') as f:
            f.write(json.dumps(diagram_data))

        self.generate_diagram(states, self.transitions, output_filename)

    def recreate_diagram(self, data, hook, output_filename):
        raw_states = data['states']
        raw_transitions = data['transitions']

        states = []
        transitions = []

        for state in raw_states:
            old_state = TCPState(
                state['name'],
                state['info'],
                state['data'],
                state['flags'],
                state['seq'],
                state['ack'],
                state['idx']
            )

            states.append(old_state)

        for tr in raw_transitions:
            old_tr = Transition(
                tr['src_state_id'],
                tr['dst_state_id'],
                tr['operation'],
                tr['arrow'],
                tr['idx'],
            )

            transitions.append(old_tr)

        if hook is not None:
            states, transitions = hook(states, transitions)

        self.generate_diagram(states, transitions, output_filename)

    def generate_diagram(self, states, transitions, output_filename):
        diagram = UMLStateDiagram()

        for state in states:
            diagram.add_state(state.idx, state.get_name())

            if state.info != None:
                diagram.add_state_data(state.idx, state.get_info())

        for tr in transitions:
            diagram.add_transition(tr.src_state_idx, tr.dst_state_idx, tr.op, tr.arrow)

        diagram.create_diagram(output_filename=output_filename)

