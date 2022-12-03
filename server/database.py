import logging
import sqlite3
import protocol


class Client:
    """ Represents a client entry """

    def __init__(self, cid, cname, public_key, last_seen):
        self.ID = bytes.fromhex(cid)  # Unique client ID, 16 bytes.
        self.Name = cname  # Client's name, null terminated ascii string, 255 bytes.
        self.PublicKey = public_key  # Client's public key, 160 bytes.
        self.LastSeen = last_seen  # The Date & time of client's last request.
        self.AesKey = None

    def validate(self):
        """ Validate Client attributes according to the requirements """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.PublicKey or len(self.PublicKey) != protocol.PUBLIC_KEY_SIZE:
            return False
        if not self.LastSeen:
            return False
        return True


class Files:
    """ Represents a file entry """

    def __init__(self, cid, file_name, path_name, verified):
        self.ID = cid  # Unique client ID, 16 bytes.
        self.Name = file_name  # File's name, null terminated ascii string, 255 bytes.
        self.Path = path_name  # File's path name, null terminated ascii string, 255 bytes.
        self.ChkSum = verified  # bool if chksum is valid

    def validate(self):
        """ Validate file attributes according to the requirements """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.Path or len(self.Path) >= protocol.NAME_SIZE:
            return False
        return True


class Database:
    CLIENTS = 'clients'
    FILES = 'files'

    def __init__(self, name):
        self.name = name

    def connect(self):
        conn = sqlite3.connect(self.name)  # doesn't raise exception.
        conn.text_factory = bytes
        return conn

    def executescript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass  # table might exist already
        conn.close()

    def execute(self, query, args, commit=False, get_last_row=False):
        """ Given an query and args, execute query, and return the results. """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            if get_last_row:
                results = cur.lastrowid  # special query.
        except Exception as e:
            logging.exception(f'database execute: {e}')
        conn.close()  # commit is not required.
        return results

    def initialize(self):
        # Try to create Clients table
        self.executescript(f"""
            CREATE TABLE {Database.CLIENTS}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              Name CHAR(255) NOT NULL,
              PublicKey CHAR(160) NOT NULL,
              LastSeen DATE,
              AesKey CHAR(32)
            );
            """)

        # Try to create Files table

        self.executescript(f"""
            CREATE TABLE {Database.FILES}(
             ID CHAR(16) NOT NULL PRIMARY KEY,
             Name CHAR(255) NOT NULL,
             Path CHAR(255) NOT NULL,
             ChkSum BOOLEAN  NOT NULL,
             FOREIGN KEY(ID) REFERENCES {Database.CLIENTS}(ID)
                   );
                   """)

    def clientUsernameExists(self, username):
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [username])
        if not results:
            return False
        return len(results) > 0

    def storeClient(self, clnt):
        if not type(clnt) is Client or not clnt.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [clnt.ID, clnt.Name, clnt.PublicKey, clnt.LastSeen, None], True)

    def clientIdFileExists(self, cid):
        results = self.execute(f"SELECT * FROM {Database.FILES} WHERE ID = ?", [cid])
        if not results:
            return False
        return len(results) > 0

    def storeFile(self, file):
        if not type(file) is Files or not file.validate():
            return False
        results = self.execute(f"INSERT INTO {Database.FILES} VALUES (?, ?, ?, ?)",
            [file.ID, file.Name, file.Path, file.ChkSum], True)
        return results

    def setLastSeen(self, client_id, time):
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [time, client_id], True)

    def getAesKeyByClientId(self, id):
        """ given a client id, return a Aes key. """
        results = self.execute(f"SELECT AesKey FROM {Database.CLIENTS} WHERE ID = ?", [id])
        if not results:
            return None
        return results[0][0]

    def setAESKey(self, id, key):
        return self.execute(f"UPDATE {Database.CLIENTS} SET AesKey = ? WHERE ID = ?",
                            [key, id], True)

    def updateValidCRC(self, id):
        return self.execute(f"UPDATE {Database.FILES} SET ChkSum = ? WHERE ID = ?",
                            [True, id], True)
