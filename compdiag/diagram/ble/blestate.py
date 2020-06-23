import json

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.basediagram import Diagram
from compdiag.diagram.transciever import Transciever
from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition

from compdiag.diagram.ble.bleutils import *

class BLEStateDiagram(Diagram):
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

        # Separate packets into requests and responses.
        requests  = []
        responses = []
        
        for pkt in pkts:
            if 'btatt' not in pkt:
                continue
            
            try:
                opcode = get_opcode(pkt)
            except ValueError:
                continue

            if (opcode == ATTOpcode.MTURequest or
                opcode == ATTOpcode.MTUResponse or
                opcode == ATTOpcode.UnknownOpcode):
                continue

            if 'error_code' in pkt.btatt.field_names:
                error_code = get_error_opcode(pkt)

            # Skip discovery packets, not relevat in data flow.
            if (ATTOpcode.isDiscoveryOpcode(opcode) or
                    (opcode == ATTOpcode.ErrorResponse and
                    error_code == ATTError.AttributeNotFound)):
                continue

            # Save entity if it does not exist
            self.update_entities(pkt)
            if self.src not in self.trx.keys():
                self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
                self.trx[self.src].states.append(init_state)
            
            if self.dst not in self.trx.keys():
                self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
                self.trx[self.dst].states.append(init_state)
            
            if ATTOpcode.isResponse(opcode):
                responses.append(pkt)
            else:
                requests.append(pkt)

        transition = ''
        for i, pkt in enumerate(requests):
            # if 'btatt' not in pkt:
            #     continue

            try:
                opcode = get_opcode(pkt)
            except ValueError:
                continue

            # # Skip MTU messages and unknown opcodes.
            # if (opcode == ATTOpcode.MTURequest or
            #     opcode == ATTOpcode.MTUResponse or
            #     opcode == ATTOpcode.UnknownOpcode):
            #     continue

            self.update_entities(pkt)

            # # Save entity if it does not exist
            # if self.src not in self.trx.keys():
            #     self.trx[self.src] = Transciever(self.src, UMLStateDiagram.ARROW_DIR_RIGHT)
            #     self.trx[self.src].states.append(init_state)
            
            # if self.dst not in self.trx.keys():
            #     self.trx[self.dst] = Transciever(self.dst, UMLStateDiagram.ARROW_DIR_LEFT)
            #     self.trx[self.dst].states.append(init_state)

            # if 'error_code' in pkt.btatt.field_names:
            #     error_code = get_error_opcode(pkt)

            # # Skip discovery packets, not relevat in data flow.
            # if (ATTOpcode.isDiscoveryOpcode(opcode) or
            #         (opcode == ATTOpcode.ErrorResponse and
            #         error_code == ATTError.AttributeNotFound)):
            
            transition += get_operation(pkt) + '\\n'
            payload = None

            if 'value' in pkt.btatt.field_names: 
                payload = pkt.btatt.value.replace(':', ' ')

            if (opcode == ATTOpcode.WriteRequest or
                opcode == ATTOpcode.WriteCommand):
                # A write is only part of the transition, does not create a state.
                continue

            elif (opcode == ATTOpcode.HandleValueNotification or
                opcode == ATTOpcode.HandleValueIndication):
                # Asynchronous operation.
                pass
            else:
                response = BLEStateDiagram.find_response(responses, pkt)
                if response is None:
                    continue

                # Request failed, append reason.
                if get_opcode(response) == ATTOpcode.ErrorResponse:
                    transition += get_operation(response) + ': ' + get_error_opcode(response).name + '\\n'
                    continue

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                #data_sent = State(self.src, 'DATA sent', payload)
                data_sent = State(self.src, None, payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                #data_recv = State(self.dst, 'DATA recv', payload)
                data_recv = State(self.dst, None, payload)
                self.trx[self.dst].states.append(data_recv)

            # Add transitions between states
            self.transitions.append(Transition(last_src_state.idx,
                                               data_sent.idx,
                                               None,
                                               UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(last_dst_state.idx,
                                               data_recv.idx,
                                               None,
                                               UMLStateDiagram.ARROW_DIR_DOWN))

            if payload:
                transition += ' '
                if len(payload) > 20: transition += payload[:24] + '...'
                else: transition += payload

            # Add message arrow
            self.transitions.append(Transition(data_sent.idx,
                                               data_recv.idx,
                                               transition,
                                               self.trx[self.src].arrow))
            transition = ''

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(Transition(self.trx[self.src].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(self.trx[self.dst].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        #self.save_diagram_data(states, self.transitions, output_filename)
        generate_diagram(states, self.transitions, output_filename)

    @staticmethod
    def find_response(arr, packet):
        request_opcode  = get_opcode(packet)
        response_opcode = ATTOpcode.getComplementaryOpcode(request_opcode)

        if not response_opcode:
            return None

        for i, response in enumerate(arr):
            if int(response.btatt.opcode, 16) == ATTOpcode.MTUResponse:
                continue

            #print(packet.btatt.handle)
            if response.btatt.handle == packet.btatt.handle:

                if (get_opcode(response) == ATTOpcode.ErrorResponse and
                    get_req_opcode_in_error(response) == request_opcode):

                    # Error found.
                    return arr.pop(i)

                if get_opcode(response) == response_opcode:
                    # Response found.
                    return arr.pop(i)
            
        return None