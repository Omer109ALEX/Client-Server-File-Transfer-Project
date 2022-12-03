#pragma once

#ifndef client_H_
#define client_H_

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <boost/filesystem.hpp>
#include <vector>
#include "protocol.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include <filesystem>
#include "crcLinux.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>

using boost::asio::ip::tcp;

#define MaxNameLenth 255
#define clientVersion '3'

constexpr auto CLIENT_INFO = "me.info.txt";   // Should be located near exe file.
constexpr auto TRANSFER_INFO = "transfer.info.txt";  // Should be located near exe file.

class client {

private:
	int _not_valid_crc_counter;
	std::string _address;
	std::string _port;
	std::string _username;
	std::string _file_path;
	std::string _public_key;
	std::string _aes_key;
	tcp::socket* _socket;
	boost::asio::io_context* _ioContext;
	bool _bigEndian;
	SClientID _client_id;
	RSAPrivateWrapper* _rsaDecryptor;
	AESWrapper* _aesDecryptor;

public:
	//constructor
	client();

	//requests steps
	void read_from_transfer_info();
	bool registration_request();
	bool generate_RSA_and_send_public_key();
	bool encrypt_and_send_file();
	csize_t crc_calculator(std::string filePath);
	bool crc_response(bool validCRC); // returns false if not Succeeded to send valid CRC in MAX 4 times (include first)

	//communicating with server funcs
	bool start_connection();
	void end_connection();
	bool sendReceive(const uint8_t* const toSend, const size_t size, uint8_t* const response, const size_t resSize);
	bool send(const uint8_t* const buffer, const size_t size) const;
	bool receive(uint8_t* const buffer, const size_t size) const;
	bool sendReceiveUnknownPayloadAesKey(const uint8_t* const request, const size_t reqSize, const EResponseCode expectedCode, uint8_t*& payload, size_t& size);

	//utils func
	void swapBytes(uint8_t* const buffer, size_t size) const;
	static std::string hex(const uint8_t* buffer, const size_t size);

};

#endif /* #define client_H_ */