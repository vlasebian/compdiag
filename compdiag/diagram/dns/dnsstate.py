import json

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

class DNSStateDiagram():
    def __init__(self):
        self.trx = {}
        self.transitions = []

        self.src = None
        self.dst = None

    def update_entities(self, pkt):
        if 'udp' in pkt:
            self.src, self.dst = (
                pkt.ip.src + ':' + pkt.udp.srcport,
                pkt.ip.dst + ':' + pkt.udp.dstport
            )
        if 'tcp' in pkt:
            self.src, self.dst = (
                pkt.ip.src + ':' + pkt.tcp.srcport,
                pkt.ip.dst + ':' + pkt.tcp.dstport
            )
    
    def is_query(self, pkt):
        return pkt.dns.flags_response == '0'

    def create_diagram(self, pkts, output_filename):

        init_state = State('START', None, None)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        for i, pkt in enumerate(pkts):
            if 'dns' not in pkt:
                continue

            self.update_entities(pkt)

            # if (self.trx and 
            #         (self.src not in self.trx.keys() or
            #          self.dst not in self.trx.keys())):
            #     continue
            
            # Save entity if it does not exist
            if self.src not in self.trx.keys():
                self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(init_state)
            
            if self.dst not in self.trx.keys():
                self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(init_state)

            pkt_type = None
            transition = ''

            if self.is_query(pkt):
                pkt_type = pkt.dns.qry_type.showname.split()[1]
                transition += pkt.dns.qry_type.showname.split()[1] + '\\n' + pkt.dns.qry_name

            else:
                pkt_type = pkt.dns.resp_type.showname.split()[1]

                if pkt_type == 'PTR':
                    transition += pkt.dns.ptr_domain_name

                if pkt_type == 'A':
                    transition += pkt.dns.a

                if pkt_type == 'SOA':
                    transition += 'mname: ' + pkt.dns.soa_mname + '\\n' + 'rname: ' + pkt.dns.soa_rname

            payload = str(pkt.dns)

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                data_sent = State(self.src, pkt_type + ' sent', payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                data_recv = State(self.dst, pkt_type + ' recv', payload)
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
            old_state = State(
                state['name'],
                state['info'],
                state['data'],
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