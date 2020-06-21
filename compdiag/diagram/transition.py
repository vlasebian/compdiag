from compdiag.uml.statediagram import UMLStateDiagram

class Transition():
    max_idx = 0

    def __init__(self, src_state_idx, dst_state_idx, operation, arrow=UMLStateDiagram.ARROW_DIR_DOWN, idx=None):
        self.idx = idx
        self.src_state_idx = src_state_idx
        self.dst_state_idx = dst_state_idx
        self.op = operation
        self.arrow = arrow

        if self.idx is None:
            self.__assign_idx()
        else:
            if int(self.idx) > Transition.max_idx:
                Transition.max_idx = int(self.idx)

    def __assign_idx(self):
        self.idx = str(Transition.max_idx)
        Transition.max_idx += 1

    def connects_state(self, state_idx):
        return state_idx == self.src_state_idx or state_idx == self.dst_state_idx

    def get_dict(self):
        return {
            'idx'          : self.idx,
            'src_state_idx': self.src_state_idx,
            'dst_state_idx': self.dst_state_idx,
            'operation'    : self.op,
            'arrow'        : self.arrow,
        }
    
    # TODO: implement __str__() method

