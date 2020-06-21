class State():
    max_idx = 0

    def __init__(self, name, info, data, idx=None):
        self.idx  = idx
        self.name = name
        self.info = info
        self.data = data

        if not self.info:
            self.info = ''

        if self.idx is None:
            self.__assign_idx()
        else:
            if int(self.idx) > State.max_idx:
                State.max_idx = int(self.idx)

    def __assign_idx(self):
        self.idx = str(State.max_idx)
        State.max_idx += 1

    def get_name(self):
        #return self.name
        return self.idx + '| ' + self.name

    def get_info(self):
        return self.info

    def get_data(self):
        return self.data

    def get_dict(self):
        return {
            'idx' : self.idx,
            'name': self.name,
            'info': self.info,
            'data': self.data,
        }

    # TODO: implement __str__() method

