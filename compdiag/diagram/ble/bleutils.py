""" 
TODO: docstring
"""
from enum import IntEnum


class SMPOpcode(IntEnum):
    """
    Bluetooth Security Manager Protocol opcodes.
    """

    Null = 0x00
    PairingRequest = 0x01
    PairingResponse = 0x02
    ParingConfirm = 0x03
    PairingRandom = 0x04
    PairingFailed = 0x05
    EncryptionInformation = 0x06
    MasterIdentification = 0x07
    IdentityInformation = 0x08
    IdentityAddressInformation = 0x09
    SigningInformation = 0x0a
    SecurityRequest = 0x0b
    PairingPublicKey = 0x0c
    PairingDHKeyCheck = 0x0d
    PairingKeypressNotification = 0x0e
    UnknownOpcode = 0x99


class SMPReason(IntEnum):
    """
    Bluetooth Security Manager reason codes.
    """
    Null = 0x00
    PasskeyEntryFailed = 0x01
    OOBNotAvailable = 0x02
    AuthenticationRequirements = 0x03
    ConfirmValueFailed = 0x04
    PairingNotSupported = 0x05
    EncryptionKeySize = 0x06
    CommandNotSupported = 0x07
    UnspecifiedReason = 0x08
    RepeatedAttempts = 0x09
    InvalidParameters = 0x0a
    DHKeyCheckFailed = 0x0b
    NumericComparisonFailed = 0x0c
    BDEDRPairingInProgress = 0x0d
    CrossTransportKeyDGNotAllowed = 0x0e  # DG - Derivation/Generation


class ATTOpcode(IntEnum):
    '''
    Bluetooth Attribute Protocol opcodes.
    '''
    Null = 0x00
    ErrorResponse = 0x01
    MTURequest = 0x02
    MTUResponse = 0x03
    FindInfoRequest = 0x04
    FindInfoResponse = 0x05
    FindByTypeValueRequest = 0x06
    FindByTypeValueResponse = 0x07
    ReadByTypeRequest = 0x08
    ReadByTypeResponse = 0x09
    ReadRequest = 0x0a
    ReadResponse = 0x0b
    ReadBlobRequest = 0x0c
    ReadBlobResponse = 0x0d
    ReadMultipleRequest = 0x0e
    ReadMultipleResponse = 0x0f
    ReadByGroupTypeRequest = 0x10
    ReadByGroupTypeResponse = 0x11
    WriteRequest = 0x12
    WriteResponse = 0x13
    PrepareWriteRequest = 0x16
    PrepareWriteResponse = 0x17
    ExecuteWriteRequest = 0x18
    ExecuteWriteResponse = 0x19
    HandleValueNotification = 0x1b
    HandleValueIndication = 0x1d
    HandleValueConfirmation = 0x1e
    WriteCommand = 0x52
    SignedWriteCommand = 0xd2
    UnknownOpcode = 0x99

    @staticmethod
    def isDiscoveryOpcode(opcode):
        discoveryOpcodes = [
            ATTOpcode.FindInfoRequest,
            ATTOpcode.FindInfoResponse,
            ATTOpcode.FindByTypeValueRequest,
            ATTOpcode.FindByTypeValueResponse,
            ATTOpcode.ReadByTypeRequest,
            ATTOpcode.ReadByTypeResponse,
            ATTOpcode.ReadByGroupTypeRequest,
            ATTOpcode.ReadByGroupTypeResponse,
        ]

        return opcode in discoveryOpcodes

    @staticmethod
    def isRequest(opcode):
        requestOpcodes = [
            ATTOpcode.MTURequest,
            ATTOpcode.FindInfoRequest,
            ATTOpcode.FindByTypeValueRequest,
            ATTOpcode.ReadByTypeRequest,
            ATTOpcode.ReadRequest,
            ATTOpcode.ReadBlobRequest,
            ATTOpcode.ReadMultipleRequest,
            ATTOpcode.PrepareWriteRequest,
            ATTOpcode.ExecuteWriteRequest,
            ATTOpcode.ReadByGroupTypeRequest,
            ATTOpcode.WriteRequest,
        ]

        return opcode in requestOpcodes

    @staticmethod
    def isResponse(opcode):
        responseOpcodes = [
            ATTOpcode.MTUResponse,
            ATTOpcode.ErrorResponse,
            ATTOpcode.FindInfoResponse,
            ATTOpcode.FindByTypeValueResponse,
            ATTOpcode.ReadByTypeResponse,
            ATTOpcode.ReadResponse,
            ATTOpcode.ReadBlobResponse,
            ATTOpcode.ReadMultipleResponse,
            ATTOpcode.PrepareWriteResponse,
            ATTOpcode.ExecuteWriteResponse,
            ATTOpcode.ReadByGroupTypeResponse,
            ATTOpcode.WriteResponse,
        ]

        return opcode in responseOpcodes

    @staticmethod
    def getComplementaryOpcode(opcode):
        '''
        Returns response opcode for given request opcode.
        '''

        if not ATTOpcode.isRequest(opcode):
            return ATTOpcode.Null

        if opcode == ATTOpcode.MTURequest:
            return ATTOpcode.MTUResponse

        if opcode == ATTOpcode.ReadRequest:
            return ATTOpcode.ReadResponse

        if opcode == ATTOpcode.WriteRequest:
            return ATTOpcode.WriteResponse

        # TODO: write the rest of the responses

        return ATTOpcode.Null


class ATTError(IntEnum):
    '''
    Bluetooth Attribute Protocol error codes.
    '''
    InvalidHandle = 0x01
    ReadNotPermitted = 0x02
    WriteNotPermitted = 0x03
    InvalidPDU = 0x04
    InsufficientAuthentication = 0x05
    RequestNotSupported = 0x06
    InvalidOffset = 0x07
    InsufficientAuthorization = 0x08
    PrepareQueueFull = 0x09
    AttributeNotFound = 0x0a
    AttributeNotLong = 0x0b
    InsufficientEncryptionKeySize = 0x0c
    InvalidAttributeValueLength = 0x0d
    UnlikelyError = 0x0e
    InsufficientEncryption = 0x0f
    UnsupportedGroupType = 0x10
    InsufficientResources = 0x11
    ApplicationError = 0x80
    ImproperCCCDescriptor = 0xfd  # CCC stands for Client Characteristic Configuration
    ProcedureAlreadyInProgress = 0xfe
    OutOfRange = 0xff

    @staticmethod
    def isDiscoveryError(opcode) -> bool:
        errorOpcodes = [
            ATTError.AttributeNotFound,
        ]

        return opcode in errorOpcodes


class UnknownPacketFormat(ValueError):
    pass


def get_opcode(packet):
    if 'btatt' in packet:
        return ATTOpcode(int(packet.btatt.opcode, 16))

    if 'btsmp' in packet:
        return SMPOpcode(int(packet.btsmp.opcode, 16))

    raise UnknownPacketFormat()


def get_error_opcode(packet):
    return ATTError(int(packet.btatt.error_code, 16))


def get_req_opcode_in_error(packet):
    return ATTOpcode(int(packet.btatt.req_opcode_in_error, 16))


def get_direction(packet):
    if 'hci_h4' in packet:
        return int(packet.hci_h4.direction, 16)

    raise UnknownPacketFormat()


def get_operation(packet):
    if 'btsmp' not in packet and 'btatt' not in packet:
        raise UnknownPacketFormat

    operation = get_opcode(packet).name

    if 'btsmp' in packet:
        return operation

    if 'handle' not in packet.btatt.field_names:
        return operation

    if int(packet.hci_h4.direction, 16) == 0x00:
        link_word = ' on '
    else:
        link_word = ' from '

    return operation + link_word + '0x' + packet.btatt.handle[-4:]
