from analyser.uml.statediagram        import UMLStateDiagram

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

class BLEStateDiagram():
    def __init__(self):
        self.trx = {}
        self.transitions = []

        self.src = None
        self.dst = None

    def update_entities(self, pkt):
        if pkt.hci_h4.direction.showname_value == 'Sent (0x00)':
            self.src = 'localhost()'
            self.dst = 'remote()'
        else:
            self.src = 'remote()'
            self.dst = 'localhost()'

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

    @staticmethod
    def create_diagram(packets):
        diagram = StateDiagram()

        # Separate packets into requests and responses.
        requests  = []
        responses = []
        
        for packet in packets:
            if 'btatt' not in packet:
                continue
            
            opcode = get_opcode(packet)
            if 'error_code' in packet.btatt.field_names:
                error_code = get_error_opcode(packet)

            # Skip discovery packets, not relevat in data flow.
            if (ATTOpcode.isDiscoveryOpcode(opcode) or
                    (opcode == ATTOpcode.ErrorResponse and
                    error_code == ATTError.AttributeNotFound)):
                continue
            
            if ATTOpcode.isResponse(opcode):
                responses.append(packet)
            else:
                requests.append(packet)

        states = []
        message_count = 0

        transition = ''
        last_state = {}

        # Each request will affect states depending on the response received,
        # but not every requests gets a response back (e.g. Write Command).
        for request in requests:
            opcode = get_opcode(request)

            # Skip MTURequest messages and unknown opcodes.
            if (opcode == ATTOpcode.MTURequest or
                opcode == ATTOpcode.UnknownOpcode):
                continue

            transition += '**' + str(message_count) + '**' + ' ' + get_operation(request) + '\\n'
            message_count += 1

            data = None
            if (opcode == ATTOpcode.WriteRequest or
                opcode == ATTOpcode.WriteCommand):
                # A write is only part of the transition, does not create a state.
                continue

            elif (opcode == ATTOpcode.HandleValueNotification or
                opcode == ATTOpcode.HandleValueIndication):
                # Asynchronous operation.
                data = request.btatt.value.replace(':', ' ')

            else:
                response = BLEStateDiagram.find_response(responses, request)
                if response is None:
                    continue

                # Request failed, append reason.
                if get_opcode(response) == ATTOpcode.ErrorResponse:
                    transition += get_operation(response) + ': ' + get_error_opcode(response).name + '\\n'
                    continue

                if 'value' in response.btatt.field_names: 
                    data = response.btatt.value.replace(':', ' ')
                else:
                    data = None


            # If state already exists, only add a transition, do not create a new state.
            old_state = BLEStateDiagram.state_exists(states, data)
            if old_state is not None:
                diagram.add_transition(last_state['name'], old_state['name'], transition)
                last_state = old_state

                transition = ''
                continue

            # Create a new state if data was not found.
            new_state = {
                'name': 'state_' + str(len(states)),
                'data': data,
            }

            if not states:
                diagram.add_transition('[*]', new_state['name'], transition)
            else:
                diagram.add_transition(last_state['name'], new_state['name'], transition)

            if data is not None:
                diagram.add_state_data(new_state['name'], data)

            transition = ''
            last_state = new_state

            states.append(new_state)
            
        diagram.create_diagram(output_filename='blestate')

    @staticmethod
    def find_response(arr, packet):
        request_opcode  = get_opcode(packet)
        response_opcode = ATTOpcode.getComplementaryOpcode(request_opcode)

        if not response_opcode:
            return None

        for i, response in enumerate(arr):
            if int(response.btatt.opcode, 16) == ATTOpcode.MTUResponse:
                continue

            print(packet.btatt.handle)
            if response.btatt.handle == packet.btatt.handle:

                if (get_opcode(response) == ATTOpcode.ErrorResponse and
                    get_req_opcode_in_error(response) == request_opcode):

                    # Error found.
                    return arr.pop(i)

                if get_opcode(response) == response_opcode:
                    # Response found.
                    return arr.pop(i)
            
        return None

    @staticmethod
    def state_exists(states, data):
        for state in states:
            if state['data'] == data:
                return state
        return None
