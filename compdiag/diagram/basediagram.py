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
        raise NotImplementedError()

    def create_diagram(self, pkts, output_filename):
        raise NotImplementedError()

    def save_diagram_data(self, states, transitions, output_filename):
        diagram_data = {
            'states':      [state.get_dict() for state in states],
            'transitions': [tr.get_dict() for tr in self.transitions],
        }

        with open(output_filename + '.json', 'w') as f:
            f.write(json.dumps(diagram_data))

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

class Reconstruct():
    pass