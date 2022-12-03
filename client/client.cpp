#include "client.h"

using boost::asio::ip::tcp;
using boost::asio::io_context;


constexpr size_t PACKET_SIZE = 65535; // max TCP packet size

//constructor
client::client()
{
    _not_valid_crc_counter = 0;

    union   // Test for endianness
    {
        uint32_t i;
        uint8_t c[sizeof(uint32_t)];
    }tester{ 1 };
    _bigEndian = (tester.c[0] == 0);

    read_from_transfer_info();
    _rsaDecryptor = new RSAPrivateWrapper();
    
}

//requests steps
bool client::registration_request()
{
    try
    {
        std::ifstream in(CLIENT_INFO);
        if (in.good()) {
            end_connection();
            throw std::exception("The client is already had registed\n");
        }

        SRequestRegistration  request;
        SResponseRegistration response;

        // fill request data
        request.header.payloadSize = sizeof(request.payload);
        strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, _username.c_str());

        //debug:
        std::cout << "request code: " << request.header.code << std::endl;

        //send and recive from server
        if (!sendReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
            reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
            throw std::exception("Failed communicating with server\n");
        
        //debug:
        std::cout <<"response code: " << response.header.code << std::endl;
        

        if (response.header.code == RESPONSE_REGISTRATION_FAILED)
            throw std::exception("The server reject the registration request \n");

        if (response.header.code != RESPONSE_REGISTRATION_SUCCEEDED)
            throw std::exception("The server response to the registration with no succeed\n");

        // store received client's ID
        _client_id = response.payload;

         //creat me.info
        std::ofstream outfile(CLIENT_INFO);
        outfile << _username.c_str() << std::endl;
        // use payload to hex format as asked
        const auto hexifiedUUID = hex(_client_id.uuid, sizeof(_client_id.uuid));
        outfile << hexifiedUUID << std::endl;
        // use rsaWrapper from course web
        const auto privatekey = _rsaDecryptor->getPrivateKey();
        const auto encodedKey = Base64Wrapper::encode(privatekey);
        outfile << reinterpret_cast<const uint8_t*>(encodedKey.c_str()) << std::endl;
        outfile.close();
        return true;


    }

    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        return false;
    }

}

bool client::generate_RSA_and_send_public_key()
{
    try
    {
        const auto publicKey = _rsaDecryptor->getPublicKey();
        if (publicKey.size() != PUBLIC_KEY_SIZE)
        {
            throw std::exception("Invalid public key length!\n");
        }

        SRequestPublicKey  request(_client_id);

        // fill request data
        request.header.payloadSize = sizeof(request.payload);
        strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, _username.c_str());
        memcpy(request.payload.clientPublicKey.publicKey, publicKey.c_str(), sizeof(request.payload.clientPublicKey.publicKey));

        //parameters for built the response
        uint8_t* payload = nullptr;
        uint8_t* ptr = nullptr;
        size_t payloadSize = 0;

        //debug:
        std::cout << "request code: " << request.header.code << std::endl;

        //send and recive from server, useing unknow response size because simetric key lenght
        if (!sendReceiveUnknownPayloadAesKey(reinterpret_cast<uint8_t*>(&request), sizeof(request),
            RESPONSE_AES_KEY, payload, payloadSize))
            throw std::exception("Failed communicating with server\n");

        ptr = payload;

        //we dont need the client id agian
        ptr += CLIENT_ID_SIZE;

        _aes_key = _rsaDecryptor->decrypt((char*)(ptr), payloadSize - CLIENT_ID_SIZE);
        const size_t keySize = _aes_key.size();

        if (keySize != SYMMETRIC_KEY_SIZE)
            throw std::exception("Invalid symmetric key size \n");

        _aesDecryptor = new AESWrapper((unsigned char*)_aes_key.c_str(), _aes_key.size());

        return true;

    }
    

    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        return false;
    }
}

void client::read_from_transfer_info()
{

    //read data from transfer.info file for start
    try
    {
        std::ifstream in(TRANSFER_INFO);
        if (in.fail())
            throw std::exception("while accessing transfer.info file\n");
        std::string iport;
        getline(in, iport);
        getline(in, _username);
        if (_username.length() >= CLIENT_NAME_SIZE)
            throw std::exception("Invalid username length!\n");
        getline(in, _file_path);
        size_t portColonPos = iport.find(':');
        _address = iport.substr(0, portColonPos);
        _port = iport.substr(portColonPos + 1);
    }

    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

}

bool client::encrypt_and_send_file()
{
    try
    {

        SRequestSendFile request(_client_id);
        SResponseFileSent response;
        uint8_t* content = nullptr;

        boost::filesystem::path p(_file_path);
        strcpy_s(reinterpret_cast<char*>(request.payloadHeader.fileName), FILE_NAME_SIZE, p.filename().string().c_str());

        std::ifstream input_file(_file_path, std::ios::binary);

        if (!input_file.is_open())
            throw std::exception("Could not open the file from requested file path\n");

        std::string file_as_string = std::string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
        std::string encrypted_file = _aesDecryptor->encrypt(file_as_string.c_str(), file_as_string.size());
        request.payloadHeader.contentSize = encrypted_file.size();

        content = new uint8_t[request.payloadHeader.contentSize];
        memcpy(content, encrypted_file.c_str(), request.payloadHeader.contentSize);

        
        //prepare request to send
        size_t reqSize;
        uint8_t* reqToSend;
        request.header.payloadSize = sizeof(request.payloadHeader) + request.payloadHeader.contentSize;
        if (content == nullptr)
        {
            reqToSend = reinterpret_cast<uint8_t*>(&request);
            reqSize = sizeof(request);
        }
        else
        {
            reqToSend = new uint8_t[sizeof(request) + request.payloadHeader.contentSize];
            memcpy(reqToSend, &request, sizeof(request));
            memcpy(reqToSend + sizeof(request), content, request.payloadHeader.contentSize);
            reqSize = sizeof(request) + request.payloadHeader.contentSize;
        }

        //debug:
        std::cout << "request code: " << request.header.code << std::endl;

        // send request and receive response
        if (!sendReceive(reqToSend, reqSize, reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
        {
            delete[] content;
            if (reqToSend != reinterpret_cast<uint8_t*>(&request))
                delete[] reqToSend;
            throw std::exception("Failed communicating with server \n");
        }

        //debug:
        std::cout << "response code: " << response.header.code << std::endl;

        delete[] content;
        if (reqToSend != reinterpret_cast<uint8_t*>(&request))  // check if reqToSend was allocated by current code.
            delete[] reqToSend;

        // Validate header
        if (response.header.code != RESPONSE_VALID_FILE_WITH_CRC)
            throw std::exception("No CRC send back after receiveing the file \n");
        
        // CRC calculate
        csize_t file_crc = crc_calculator(_file_path);
        bool validCRC = (response.payload.crc == file_crc);
        return crc_response(validCRC);
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        return false;
    } 
}

bool client::crc_response(bool validCRC)
{
    code_t reqCode = DEF_VAL;
    bool send_another_try = false;


    if (validCRC)
        reqCode = REQUEST_VALID_CRC;
    else
    {
        _not_valid_crc_counter++;
        if (_not_valid_crc_counter >= MAX_SEND_FILES_REQUESTS)
            reqCode = REQUEST_NOT_VALID_CRC_4TIME_FINISH;
        else {
            reqCode = REQUEST_NOT_VALID_CRC_TRY_AGIAN;
            send_another_try = true;
        }
       
    }

    SRequestAfterNotValidCRC request(_client_id, reqCode);

    //debug:
    std::cout << "request code: " << request.header.code << std::endl;

    // send request, by protocol there is no need to get response
    request.header.payloadSize = sizeof(request.payload);
    boost::filesystem::path p(_file_path);
    strcpy_s(reinterpret_cast<char*>(request.payload.fileName), FILE_NAME_SIZE, p.filename().string().c_str());
    if (!start_connection())
        std::cout << "Failed start connection with the server" << std::endl;
    if (!send(reinterpret_cast<const uint8_t* const>(&request), sizeof(request)))
        std::cout << "Failed send the message to the server" << std::endl;

    //receive response 2104 from server, its only header [by protocol]
    if (validCRC)
    {
        SResponseHeader response;
        if (!receive(reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
            std::cout << "Failed receive the message from the server" << std::endl;
        //debug:
        std::cout << "response code: " << response.code << std::endl;
    }

    end_connection();

    
    if (send_another_try)
        return encrypt_and_send_file();

    return validCRC;

}

csize_t client::crc_calculator(std::string filePath)
{
    try
    {

        CRC crc = CRC();
        std::ifstream input_file(filePath, std::ios::binary);
        if (!input_file.is_open())
            throw std::exception("Could not open the file from requested file path\n");

        std::string file_as_string = std::string((std::istreambuf_iterator<char>(input_file)),
                std::istreambuf_iterator<char>());

        crc.update((unsigned char*)file_as_string.c_str(), file_as_string.size());

        return crc.digest();

    }


    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        return false;
    }
}


//communicating with server funcs
bool client::start_connection()
{
    try
    {
        end_connection();
        //client socket information for connection
        _ioContext = new boost::asio::io_context;
        _socket = new tcp::socket(*_ioContext);
        tcp::resolver resolver(*_ioContext);
        boost::asio::connect(*_socket, resolver.resolve(_address, _port));
        return true;

    }

    catch (std::exception& e)
    {
        std::cerr << "server responded with an error: " << e.what() << "\n";
        return false;
    }
}

void client::end_connection()
{
    try
    {
        if (_socket != nullptr)
            _socket->close();
    }
    catch (std::exception& e)
    {
        std::cerr << "server responded with an error: " << e.what() << "\n";
    }    delete _ioContext;
    delete _socket;
    _ioContext = nullptr;
    _socket = nullptr;
}

bool client::sendReceive(const uint8_t* const toSend, const size_t size, uint8_t* const response, const size_t resSize)
{
    if (!start_connection())
    {
        return false;
    }
    if (!send(toSend, size))
    {
        end_connection();
        return false;
    }
    if (!receive(response, resSize))
    {
        end_connection();
        return false;
    }
    end_connection();
    return true;
}

bool client::send(const uint8_t* const buffer, const size_t size) const
{
    try
    {
        size_t bytesLeft = size;
        const uint8_t* ptr = buffer;
        while (bytesLeft > 0)
        {
            uint8_t tempBuffer[PACKET_SIZE] = { 0 };
            const size_t bytesToSend = (bytesLeft > PACKET_SIZE) ? PACKET_SIZE : bytesLeft;

            memcpy(tempBuffer, ptr, bytesToSend);


            if (_bigEndian)  // It's required to convert from big endian to little endian.
            {
                swapBytes(tempBuffer, bytesToSend);
            }


            const size_t bytesWritten = write(*_socket, boost::asio::buffer(tempBuffer, PACKET_SIZE));
            if (bytesWritten == 0)
                return false;


            ptr += bytesWritten;
            bytesLeft = (bytesLeft < bytesWritten) ? 0 : (bytesLeft - bytesWritten);  // unsigned protection.
        }
        return true;
    }
    catch (std::exception& e)
    {
        std::cerr << "server responded with an error: " << e.what() << "\n";
        return false;
    }
}

bool client::receive(uint8_t* const buffer, const size_t size) const
{
    try
    {
        size_t bytesLeft = size;
        uint8_t* ptr = buffer;
        while (bytesLeft > 0)
        {

            uint8_t tempBuffer[PACKET_SIZE] = { 0 };
            boost::system::error_code errorCode; // read() will not throw exception when error_code is passed as argument.

            size_t bytesRead = read(*_socket, boost::asio::buffer(tempBuffer, PACKET_SIZE), errorCode);

            if (bytesRead == 0)
                return false;     // Error. Failed receiving and shouldn't use buffer.

            if (_bigEndian)  // It's required to convert from little endian to big endian.
            {
                swapBytes(tempBuffer, bytesRead);
            }

            const size_t bytesToCopy = (bytesLeft > bytesRead) ? bytesRead : bytesLeft;  // prevent buffer overflow.
            memcpy(ptr, tempBuffer, bytesToCopy);

            ptr += bytesToCopy;
            bytesLeft = (bytesLeft < bytesToCopy) ? 0 : (bytesLeft - bytesToCopy);  // unsigned protection.
        }

        return true;
    }

    catch (std::exception& e)
    {
        std::cerr << "server responded with an error: " << e.what() << "\n";
        return false;
    }
}

bool client::sendReceiveUnknownPayloadAesKey(const uint8_t* const request, const size_t reqSize,
    const EResponseCode expectedCode, uint8_t*& payload, size_t& size)
{
    SResponseHeader response;
    uint8_t buffer[PACKET_SIZE];
    payload = nullptr;
    size = 0;
   
    if (!start_connection())
    {
        return false;
    }
    if (!send(request, reqSize))
    {
        end_connection();
        return false;
    }
    if (!receive(buffer, sizeof(buffer)))
    {
        return false;
    }

    memcpy(&response, buffer, sizeof(SResponseHeader));
    if (response.payloadSize == 0)
        return true;  // no payload. but not an error.

    size = response.payloadSize;

    payload = new uint8_t[size];
    uint8_t* ptr = static_cast<uint8_t*>(buffer) + sizeof(SResponseHeader);
    size_t recSize = sizeof(buffer) - sizeof(SResponseHeader);
    if (recSize > size)
        recSize = size;
    memcpy(payload, ptr, recSize);
    ptr = payload + recSize;

    while (recSize < size)
    {
        size_t toRead = (size - recSize);
        if (toRead > PACKET_SIZE)
            toRead = PACKET_SIZE;
        if (!receive(buffer, toRead))
        {
            delete[] payload;
            payload = nullptr;
            size = 0;
            return false;
        }
        memcpy(ptr, buffer, toRead);
        recSize += toRead;
        ptr += toRead;
    }

    //debug:
    std::cout << "response code: " << response.code << std::endl;

    if (response.code != expectedCode)
        throw std::exception("The server response not by the expected code frome protocol\n");

    return true;
}

//utils funcs
void client::swapBytes(uint8_t* const buffer, size_t size) const
{
    if (buffer == nullptr || size < sizeof(uint32_t))
        return;

    size -= (size % sizeof(uint32_t));
    uint32_t* const ptr = reinterpret_cast<uint32_t* const>(buffer);
    for (size_t i = 0; i < size; ++i)
    {
        const uint32_t tmp = ((buffer[i] << 8) & 0xFF00FF00) | ((buffer[i] >> 8) & 0xFF00FF);
        buffer[i] = (tmp << 16) | (tmp >> 16);
    }

}

std::string client::hex(const uint8_t* buffer, const size_t size)
{
    if (size == 0 || buffer == nullptr)
        return "";
    const std::string byteString(buffer, buffer + size);
    if (byteString.empty())
        return "";
    try
    {
        return boost::algorithm::hex(byteString);
    }
    catch (...)
    {
        return "";
    }
}
