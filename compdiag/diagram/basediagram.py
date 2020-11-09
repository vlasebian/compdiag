import json
from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

class Diagram():
    def __init__(self):
        self.trx = {}
        self.transitions = []

        self.src = None
        self.dst = None

    def update_entities(self):
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

        if 'ip' in pkt:
            self.src, self.dst = (
                pkt.ip.src + ':' + pkt.tcp.srcport,
                pkt.ip.dst + ':' + pkt.tcp.dstport
            )
        elif 'ipv6' in pkt:
            self.src, self.dst = (
                pkt.ipv6.src + ':' + pkt.tcp.srcport,
                pkt.ipv6.dst + ':' + pkt.tcp.dstport
            )

        raise NotImplementedError()

    def create_diagram(self, pkts, output_filename):
        raise NotImplementedError()

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
                tr['src_state_idx'],
                tr['dst_state_idx'],
                tr['operation'],
                tr['arrow'],
                tr['idx'],
            )

            transitions.append(old_tr)

        if hook is not None:
            states, transitions = hook(states, transitions)

        self.generate_diagram(states, transitions, output_filename)

    def save_diagram_data(self, states, transitions, output_filename):
        diagram_data = {
            'states':      [state.get_dict() for state in states],
            'transitions': [tr.get_dict() for tr in transitions],
        }

        with open(output_filename + '.json', 'w') as f:
            f.write(json.dumps(diagram_data))

    def generate_diagram(self, states, transitions, output_filename):
        diagram = UMLStateDiagram()

        for state in states:
            diagram.add_state(state.idx, state.get_name())

            if state.info != None:
                diagram.add_state_data(state.idx, state.get_info())

        for tr in transitions:
            diagram.add_transition(tr.src_state_idx, tr.dst_state_idx, tr.op, tr.arrow)

        diagram.create_diagram(output_filename=output_filename)

class Reconstruct():
    ARR_DOWN  = UMLStateDiagram.ARROW_DIR_DOWN
    ARR_UP    = UMLStateDiagram.ARROW_DIR_UP
    ARR_LEFT  = UMLStateDiagram.ARROW_DIR_LEFT
    ARR_RIGHT = UMLStateDiagram.ARROW_DIR_RIGHT

    @staticmethod
    def remove_states(state_no, states, transitions):
        # FIXME
        for no in state_no:
            state_id = str(no)

            transitions = list(filter(lambda transition:
                transition.src_state_idx != state_id and
                transition.dst_state_idx != state_id, transitions))

            states = list(filter(lambda state: state.idx != state_id, states))
        
        return states, transitions

    @staticmethod
    def get_state(state_no, states):
        for state in states:
            if state.idx == str(state_no):
                return state
        return None

    @staticmethod
    def unify_states(final_state_no, state_no, states, transitions):
        final_state = Reconstruct.get_state(final_state_no, states)

        for no in state_no:
            state = Reconstruct.get_state(no, states)
            final_state.info += '\\n' + state.info

        states, transitions = Reconstruct.remove_states(state_no, states, transitions)

        return states, transitions

#### Reconstruct example
def simple_modifier(states, transitions):
    states, transitions = Reconstruct.remove_states(range(10, 40), states, transitions)

    return states, transitions
