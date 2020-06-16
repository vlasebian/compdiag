class Transciever():
    def __init__(self, idx, arrow_dir):
        self.idx    = idx
        self.states = []
        self.arrow  = arrow_dir

    def has_state(self, data):
        for state in self.states:
            if state.data == data:
                return state
        return None

