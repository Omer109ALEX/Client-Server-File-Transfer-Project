import logging
import os.path
import selectors
import uuid
import socket
import crc
import Crypto
import database
import datetime
import protocol
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA


class Server:
    DATABASE = 'server.db'
    PACKET_SIZE = 65535  # Default packet size.( max TCP packet size)
    MAX_QUEUED_CONN = 10  # Default maximum number of queued connections.
    IS_BLOCKING = False  # Do not block!

    def __init__(self, host, port):
        logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.database = database.Database(Server.DATABASE)

        """ use specific func for every kind of request """
        self.requestHandle = {
            protocol.ERequestCode.REQUEST_REGISTRATION.value: self.handleRegistrationRequest,
            protocol.ERequestCode.REQUEST_PUBLIC_KEY.value: self.handlePublicKeyRequest,
            protocol.ERequestCode.REQUEST_SEND_FILE.value: self.handleFileSendRequest,
            protocol.ERequestCode.REQUEST_VALID_CRC.value: self.handleValidCrcRequest,
            protocol.ERequestCode.REQUEST_NOT_VALID_CRC.value: self.handleNotValidCrcRequest,
            protocol.ERequestCode.REQUEST_NOT_VALID_CRC_4TIME_FINISH.value: self.handleNotValidCrc4TimesRequest,

        }

    def accept(self, sock, mask):
        conn, address = sock.accept()
        logging.info("A client has connected.")
        conn.setblocking(Server.IS_BLOCKING)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            requestHeader = protocol.RequestHeader()
            success = False
            if not requestHeader.unpack(data):
                logging.error("Failed to parse request header!")
            else:
                if requestHeader.code in self.requestHandle.keys():
                    success = self.requestHandle[requestHeader.code](conn, data)  # invoke corresponding handle.
            if not success:
                responseHeader = protocol.ResponseHeader(protocol.EResponseCode.RESPONSE_REGISTRATION_FAILED.value)
                self.write(conn, responseHeader.pack())
            self.database.setLastSeen(requestHeader.clientID, str(datetime.datetime.now()))
        self.sel.unregister(conn)
        logging.info("A client has disconnected.")
        conn.close()

    def write(self, conn, data):
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            toSend = data[sent:sent + leftover]
            if len(toSend) < Server.PACKET_SIZE:
                toSend += bytearray(Server.PACKET_SIZE - len(toSend))
            try:
                conn.send(toSend)
                sent += len(toSend)
            except:
                logging.error("Failed to send response to " + conn)
                return False
        logging.info("Response sent successfully.")
        return True

    def start(self):
        self.database.initialize()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(Server.IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            return False

        print(f"Server is listening for connections on port {self.port}..")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                logging.exception(f"Server main loop exception: {e}")

    def handleRegistrationRequest(self, conn, data):
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False
        try:
            if self.database.clientUsernameExists(request.name):
                logging.info(f"Registration Request: Username ({request.name}) already exists.")
                return False
        except:
            logging.error("Registration Request: Failed to connect to database.")
            return False

        clnt = database.Client(uuid.uuid4().hex, request.name, request.publicKey, str(datetime.datetime.now()))
        if not self.database.storeClient(clnt):
            logging.error(f"Registration Request: Failed to store client {request.name}.")
            return False
        logging.info(f"Successfully registered client {request.name}.")
        response.clientID = clnt.ID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    def handlePublicKeyRequest(self, conn, data):

        request = protocol.PublicKeyRequest()
        response = protocol.PublicKeyResponse()


        if not request.unpack(data):
            logging.error("PublicKey Request: Failed to parse request header!")

        aes_key = Crypto.Random.get_random_bytes(protocol.AES_KEY_SIZE)
        key = RSA.importKey(request.publicKey)
        cipher = PKCS1_OAEP.new(key)
        response.symmetricKey = cipher.encrypt(aes_key)
        response.clientID = request.header.clientID

        if not self.database.setAESKey(response.clientID, aes_key):  # Save the AES key in the database
            logging.error("Couldn't save the AES key in the database")
            return False

        response.header.payloadSize = protocol.CLIENT_ID_SIZE + (response.symmetricKey.__len__())
        logging.info(f"AES symmetric key response was successfully built to client ({request.name}).")
        return self.write(conn, response.pack())

    def handleFileSendRequest(self, conn, data):

        request = protocol.FileSendRequest()

        if not request.unpack(conn, data):
            logging.error("Send file Request: Failed to parse request header!")

        response = protocol.FileSentResponse(request)
        aes_key = self.database.getAesKeyByClientId(response.clientID)

        iv = bytearray([0] * AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_file = unpad(cipher.decrypt(request.content), AES.block_size)

        """ CRC calculator """
        digest = crc.crc32()
        digest.update(decrypted_file)
        response.crc = digest.digest()
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.CONTENT_SIZE + protocol.NAME_SIZE + protocol.CRC_SIZE

        """ save file on server RAM """
        fileOnServer = open(request.fileName, "wb")
        filePath = os.path.abspath(request.fileName)
        fileOnServer.write(decrypted_file)
        fileOnServer.close()

        """ store file in database """
        try:
            file = database.Files(request.header.clientID, request.fileName, filePath, False)
            if not self.database.storeFile(file):
                logging.error(f"Failed to store file: {request.fileName} , at server.")
                return False
            logging.info(f"Successfully store file: {request.fileName} , at server.")

        except:
            logging.error("Sent file Request: Failed to connect to database.")
            return False

        return self.write(conn, response.pack())

    def handleValidCrcRequest(self, conn, data):
        request = protocol.RequestHeader()
        response = protocol.ResponseHeader(protocol.EResponseCode.RESPONSE_MSG_CONFIRM.value)

        if not request.unpack(data):
            logging.error("Request Vaild CRC: Failed parsing request.")
            return False

        self.database.updateValidCRC(request.clientID)
        logging.info("The CRC that server sent was correct!")
        return self.write(conn, response.pack())

    def handleNotValidCrcRequest(self, conn, data):
        logging.info("The CRC that server sent was not correct, the client will try to send again")
        return True

    def handleNotValidCrc4TimesRequest(self, conn, data):
        logging.info("The CRC that server sent was not correct, for the 4 time so the client will stop try to send")
        return True
