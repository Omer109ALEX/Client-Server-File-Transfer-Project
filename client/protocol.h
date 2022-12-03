
#pragma once
#include <cstdint>

enum { DEF_VAL = 0 };  // Default value used to initialize protocol structures.

// Common types
typedef uint8_t  version_t;
typedef uint16_t code_t;
typedef uint32_t csize_t;  // protocol's size type: Content's, payload's and message's size, CKsum of CRC.

// Constants. All sizes are in BYTES.
constexpr version_t CLIENT_VERSION = 3;
constexpr size_t    CLIENT_ID_SIZE = 16;
constexpr size_t    CLIENT_NAME_SIZE = 255;
constexpr size_t    FILE_NAME_SIZE = 255;
constexpr size_t    FILE_CONTENT_SIZE = 4;
constexpr size_t    PUBLIC_KEY_SIZE = 160;  // defined in protocol. 1024 bits.
constexpr size_t    SYMMETRIC_KEY_SIZE = 16;   // defined in protocol.  128 bits.
constexpr size_t    MAX_SEND_FILES_REQUESTS = 4;

// Code by protocol
enum ERequestCode
{
	REQUEST_REGISTRATION = 1100,   // uuid ignored.
	REQUEST_PUBLIC_KEY = 1101,
	REQUEST_SEND_FILE = 1103,
	REQUEST_VALID_CRC = 1104,
	REQUEST_NOT_VALID_CRC_TRY_AGIAN = 1105,
	REQUEST_NOT_VALID_CRC_4TIME_FINISH = 1106,

};

enum EResponseCode
{
	RESPONSE_REGISTRATION_SUCCEEDED = 2100,
	RESPONSE_REGISTRATION_FAILED = 2101,
	RESPONSE_AES_KEY = 2102,
	RESPONSE_VALID_FILE_WITH_CRC = 2103,
	RESPONSE_MSG_CONFIRM_THANKS = 2104,

};


#pragma pack(push, 1)

// Struct by protocol
struct SClientID
{
	uint8_t uuid[CLIENT_ID_SIZE];
	SClientID() : uuid{ DEF_VAL } {}

	bool operator==(const SClientID& otherID) const {
		for (size_t i = 0; i < CLIENT_ID_SIZE; ++i)
			if (uuid[i] != otherID.uuid[i])
				return false;
		return true;
	}

	bool operator!=(const SClientID& otherID) const {
		return !(*this == otherID);
	}

};

struct SClientName
{
	uint8_t name[CLIENT_NAME_SIZE];  // DEF_VAL terminated.
	SClientName() : name{ '\0' } {}
};

struct SPublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	SPublicKey() : publicKey{ DEF_VAL } {}
};

struct SSymmetricKey
{
	uint8_t symmetricKey[SYMMETRIC_KEY_SIZE];
	SSymmetricKey() : symmetricKey{ DEF_VAL } {}
};

// Struct genral request and respone (used in all communication)
struct SRequestHeader
{
	SClientID       clientId;
	const version_t version;
	const code_t    code;
	csize_t         payloadSize;
	SRequestHeader(const code_t reqCode) : version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
	SRequestHeader(const SClientID& id, const code_t reqCode) : clientId(id), version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL) {}
};

struct SResponseHeader
{
	version_t version;
	code_t    code;
	csize_t   payloadSize;
	SResponseHeader() : version(DEF_VAL), code(DEF_VAL), payloadSize(DEF_VAL) {}
};

// Struct Registration request and respone (used in all communication)
struct SRequestRegistration
{
	SRequestHeader header;
	struct
	{
		SClientName clientName;
	}payload;
	SRequestRegistration() : header(REQUEST_REGISTRATION) {}
};

struct SResponseRegistration
{
	SResponseHeader header;
	SClientID       payload;
};

// Struct PublicKey request and respone (used in all communication)
struct SRequestPublicKey
{
	SRequestHeader header;
	struct
	{
		SClientName clientName;
		SPublicKey  clientPublicKey;
	}payload;	SRequestPublicKey(const SClientID& id) : header(id, REQUEST_PUBLIC_KEY) {}
};

struct SResponsePublicKey
{
	SResponseHeader header;
	struct
	{
		SClientID   clientId;
	}payload;
};

// Struct File request and respone (used in all communication)
struct SRequestSendFile
{
	SRequestHeader header;
	struct SPayloadHeader
	{
		SClientID           clientId;   // client that send
		csize_t             contentSize;
		uint8_t				fileName[FILE_NAME_SIZE];  // DEF_VAL terminated.
		SPayloadHeader(const SClientID& id) : clientId(id), contentSize(DEF_VAL) {}
	}payloadHeader;
	SRequestSendFile(const SClientID& id) : header(id, REQUEST_SEND_FILE), payloadHeader(id) {}
};

struct SResponseFileSent
{
	SResponseHeader header;
	struct SPayload
	{
		SClientID           clientId;   // client that send
		csize_t             contentSize;
		uint8_t				fileName[FILE_NAME_SIZE];  
		csize_t				crc;
		SPayload() : contentSize(DEF_VAL) {}
	}payload;
};

// Struct after not valid CRC request and respone (used in all communication)
struct SRequestAfterNotValidCRC
{
	SRequestHeader		header;
	struct 
	{
		SClientID           clientId;   // client that send
		uint8_t				fileName[FILE_NAME_SIZE];
	}payload;
	SRequestAfterNotValidCRC(const SClientID& id, const code_t reqCode) : header(id, reqCode) {}
};


#pragma pack(pop)