import json

from compdiag.uml.statediagram import UMLStateDiagram
from compdiag.diagram.basediagram import Diagram, generate_diagram, save_diagram_data
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

    ######## No minimization ########
    def create_diagram_O0(self, pkts):
        init_state = State('START', None, None)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

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

            # Skip discovery packets, not relevant in protocol logic
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

            transition = get_operation(pkt) + '\\n'
            payload = None
            if 'value' in pkt.btatt.field_names:
                payload = pkt.btatt.value
                payload = payload.replace(':', ' ')
                transition += ' ' + payload if len(payload) < 24 else payload[:24] + '...'

            last_src_state = self.trx[self.src].states[-1]
            last_dst_state = self.trx[self.dst].states[-1]

            data_sent = self.trx[self.src].get_state(payload)
            if data_sent is None:
                data_sent = State(self.src, 'DATA sent', payload)
                self.trx[self.src].states.append(data_sent)

            data_recv = self.trx[self.dst].get_state(payload)
            if data_recv is None:
                data_recv = State(self.dst, 'DATA recv', payload)
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

            # Add message arrow
            self.transitions.append(Transition(data_sent.idx,
                                               data_recv.idx,
                                               transition,
                                               self.trx[self.src].arrow))

        if len(self.trx[self.src].states) and len(self.trx[self.dst].states):
            self.transitions.append(Transition(self.trx[self.src].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))
            self.transitions.append(Transition(self.trx[self.dst].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        states = []
        for entity in self.trx.values():
            for state in entity.states:
                states.append(state)

        return states, self.transitions

    ####### First minimization attempt - omitting central device states ######
    def create_diagram_O1(self, pkts):
        init_state = State('START', None, None)
        # create only one entity
        self.trx['remote'] = Transciever('remote()', UMLStateDiagram.ARROW_DIR_RIGHT)
        self.trx['remote'].states.append(init_state)

        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

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

            # Skip discovery packets, not relevant in protocol logic
            if (ATTOpcode.isDiscoveryOpcode(opcode) or
                    (opcode == ATTOpcode.ErrorResponse and
                     error_code == ATTError.AttributeNotFound)):
                continue

            # Save entity if it does not exist
            transition = get_operation(pkt) + '\\n'
            payload = None
            if 'value' in pkt.btatt.field_names:
                payload = pkt.btatt.value
                payload = payload.replace(':', ' ')
                transition += ' ' + payload if len(payload) < 24 else payload[:24] + '...'

            last_state = self.trx['remote'].states[-1]

            data = self.trx['remote'].get_state(payload)
            if data is None:
                data = State('remote()', 'DATA sent', payload)
                self.trx['remote'].states.append(data)

            # Add transitions between states
            self.transitions.append(Transition(last_state.idx,
                                               data.idx,
                                               transition,
                                               UMLStateDiagram.ARROW_DIR_DOWN))

        if len(self.trx['remote'].states):
            self.transitions.append(Transition(self.trx['remote'].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        return self.trx['remote'].states, self.transitions

    ####### Second minimization attempt - generate states only on responses ######
    def create_diagram_O2(self, pkts):
        init_state = State('START', None, None)
        # create only one entity
        self.trx['remote'] = Transciever('remote()', UMLStateDiagram.ARROW_DIR_RIGHT)
        self.trx['remote'].states.append(init_state)
        self.transitions.append(Transition(None, init_state.idx, None, UMLStateDiagram.ARROW_DIR_DOWN))

        # Separate packets into requests and responses.
        requests = []
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

            if ATTOpcode.isResponse(opcode):
                responses.append(pkt)
            else:
                requests.append(pkt)

        transition = ''
        for i, pkt in enumerate(requests):
            if 'btatt' not in pkt:
                continue

            try:
                opcode = get_opcode(pkt)
            except ValueError:
                continue

            transition += get_operation(pkt) + '\\n'
            payload = None
            if 'value' in pkt.btatt.field_names:
                payload = pkt.btatt.value.replace(':', ' ')

            if (opcode == ATTOpcode.WriteRequest or
                    opcode == ATTOpcode.WriteCommand):
                # A write is only part of the transition, does not create a state.
                if payload is not None:
                    #transition += ' ' + payload + '\\n' if len(payload) < 24 else payload[:24] + '...\\n'
                    transition += ' ' + payload + '\\n'
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

                if 'value' in response.btatt.field_names:
                    payload = response.btatt.value.replace(':', ' ')

            last_state = self.trx['remote'].states[-1]
            new_state = self.trx['remote'].get_state(payload)
            if new_state is None:
                new_state = State('remote()', payload, payload)
                self.trx['remote'].states.append(new_state)

            # Add transitions between states
            self.transitions.append(Transition(last_state.idx,
                                               new_state.idx,
                                               transition,
                                               UMLStateDiagram.ARROW_DIR_DOWN))
            transition = ''

        if len(self.trx['remote'].states):
            self.transitions.append(
                Transition(self.trx['remote'].states[-1].idx, None, None, UMLStateDiagram.ARROW_DIR_DOWN))

        return self.trx['remote'].states, self.transitions

    def create_diagram(self, pkts, output_filename):
        states, transitions = self.create_diagram_O2(pkts)
        save_diagram_data(states, transitions, output_filename)
        generate_diagram(states, self.transitions, output_filename)

    @staticmethod
    def find_response(arr, packet):
        request_opcode = get_opcode(packet)
        response_opcode = ATTOpcode.getComplementaryOpcode(request_opcode)

        if not response_opcode:
            return None

        for i, response in enumerate(arr):
            if int(response.btatt.opcode, 16) == ATTOpcode.MTUResponse:
                continue

            # print(packet.btatt.handle)
            if response.btatt.handle == packet.btatt.handle:

                if (get_opcode(response) == ATTOpcode.ErrorResponse and
                        get_req_opcode_in_error(response) == request_opcode):
                    # Error found.
                    return arr.pop(i)

                if get_opcode(response) == response_opcode:
                    # Response found.
                    return arr.pop(i)

        return None
