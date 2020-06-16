class State():
    max_idx = 0

    def __init__(self, name, info, data, idx=None):
        self.idx  = idx
        self.name = name
        self.info = info
        self.data = data

        if self.idx is None:
            self.__assign_idx()
        else:
            if int(self.idx) > max_idx:
                max_idx = int(self.idx)

    def __assign_idx(self):
        self.idx = str(State.max_idx)
        State.max_idx += 1

    @property
    def idx(self):
        return self.idx

    @property
    def name(self):
        #return self.name
        return self.idx + '| ' + self.name

    @property
    def info(self):
        return self.info

    @property
    def data(self):
        return self.data

    def get_dict(self):
        return {
            'name': self.name,
            'info': self.info,
            'idx' : self.idx,
        }

