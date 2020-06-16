from analyser.uml.util import nl
from analyser.uml.base import UMLDiagram

class StateDiagram(UMLDiagram):
    ARROW_DIR_DOWN  = ' -down-> '
    ARROW_DIR_UP    = ' -up-> '
    ARROW_DIR_LEFT  = ' -left[#blue,dashed]-> '
    ARROW_DIR_RIGHT = ' -right[#blue,dashed]-> '

    def __init__(self):
        super().__init__()

        self.add_properties({
            'hide empty description': ' ',
        })

        self.add_skinparam_options({
            'wrapWidth': '256',
            'maxMessageSize': '256',
            'defaulttextalignment': 'center',
        })

    @Diagram.uml_statement
    def add_transition(self, src, dst, operation=None, arrow=None):
        if not src and not dst:
            return None 

        if not src: src = '[*]'
        if not dst: dst = '[*]'

        if arrow is None:
            arrow = ' --> '

        transition = src + arrow + dst

        if operation:
            transition += ': ' + operation

        return transition

    @Diagram.uml_statement
    def add_state(self, idx, name):
        return 'state "' + name + '" as ' + idx

    @Diagram.uml_statement
    def add_state_data(self, state, note):
        if note:
            return state + ' : ' + note
        return None

