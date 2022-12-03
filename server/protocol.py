import struct
from enum import Enum

SERVER_VERSION = 3
DEF_VAL = 0  # Default value to initialize inner fields.
HEADER_SIZE = 7  # Header size without clientID. (version, code, payload size).
CLIENT_ID_SIZE = 16
CONTENT_SIZE = 4
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 16
CRC_SIZE = 4


# Request Codes
class ERequestCode(Enum):
    REQUEST_REGISTRATION = 1100  # uuid ignored.
    REQUEST_PUBLIC_KEY = 1101
    REQUEST_SEND_FILE = 1103
    REQUEST_VALID_CRC = 1104
    REQUEST_NOT_VALID_CRC = 1105
    REQUEST_NOT_VALID_CRC_4TIME_FINISH = 1106


# Responses Codes
class EResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCEEDED = 2100
    RESPONSE_REGISTRATION_FAILED = 2101
    RESPONSE_AES_KEY = 2102
    RESPONSE_VALID_CRC = 2103
    RESPONSE_MSG_CONFIRM = 2104


class RequestHeader:
    def __init__(self):
        self.clientID = b""  # 16 byte
        self.version = DEF_VAL  # 1 byte
        self.code = DEF_VAL  # 2 bytes
        self.payloadSize = DEF_VAL  # 4 bytes
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            headerData = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", headerData)
            return True
        except:
            self.__init__()  # reset values
            return False


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION  # 1 byte
        self.code = code  # 2 bytes
        self.payloadSize = DEF_VAL  # 4 bytes
        self.SIZE = HEADER_SIZE

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.publicKey = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            keyData = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", keyData)[0]
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False


class RegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_REGISTRATION_SUCCEEDED.value)
        self.clientID = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.publicKey = b""

    def unpack(self, data):
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            keyData = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", keyData)[0]
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False


class PublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_AES_KEY.value)
        self.clientID = b""
        self.symmetricKey = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{PUBLIC_KEY_SIZE}s", self.symmetricKey)
            return data
        except:
            return b""


class FileSendRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.clientID = b""
        self.contentSize = DEF_VAL  # 4 bytes
        self.fileName = b""
        self.content = b""

    def unpack(self, conn, data):
        packetSize = len(data)
        if not self.header.unpack(data):
            return False
        try:
            clientID = data[self.header.SIZE:self.header.SIZE + CLIENT_ID_SIZE]
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", clientID)[0]
            offset = self.header.SIZE + CLIENT_ID_SIZE
            contentData = data[offset:offset + CONTENT_SIZE]
            self.contentSize = struct.unpack("<L", contentData)[0]
            offset = self.header.SIZE + CLIENT_ID_SIZE + CONTENT_SIZE
            nameData = data[offset:offset + NAME_SIZE]
            self.fileName = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            offset = self.header.SIZE + CLIENT_ID_SIZE + CONTENT_SIZE + NAME_SIZE
            bytesRead = packetSize - offset
            if bytesRead > self.contentSize:
                bytesRead = self.contentSize
            self.content = struct.unpack(f"<{bytesRead}s", data[offset:offset + bytesRead])[0]
            while bytesRead < self.contentSize:
                data = conn.recv(packetSize)  # reuse first size of data.
                dataSize = len(data)
                if (self.contentSize - bytesRead) < dataSize:
                    dataSize = self.contentSize - bytesRead
                self.content += struct.unpack(f"<{dataSize}s", data[:dataSize])[0]
                bytesRead += dataSize

            return True

        except:
            self.clientID = b""
            self.contentSize = DEF_VAL
            self.fileName = b""
            self.content = b""
            return False


class FileSentResponse:
    def __init__(self, request: FileSendRequest):
        self.header = ResponseHeader(EResponseCode.RESPONSE_VALID_CRC.value)
        self.clientID = request.header.clientID
        self.contentSize = request.contentSize
        self.fileName = request.fileName
        self.crc = DEF_VAL

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack("<L", self.contentSize)
            data += struct.pack(f"<{NAME_SIZE}s", self.fileName.encode("UTF-8"))
            data += struct.pack("<L", self.crc)
            return data

        except:
            return b""
