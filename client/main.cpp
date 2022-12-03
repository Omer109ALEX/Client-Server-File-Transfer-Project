#include "client.h"
#include "crcLinux.h"


int main()
{
    std::cout << "Hello, let's start maman 15!" << std::endl;
    client* myClient = new client();

    try
    {
        std::cout << "\nRegistration request" << std::endl;
        if (!myClient->registration_request())
            throw std::exception("Failed to register\n");

        std::cout << "\nGenerate and send RSA public key" << std::endl;
        if (!myClient->generate_RSA_and_send_public_key())
            throw std::exception("Failed to send and recive AES key\n");

        std::cout << "\nReceive encrypted AES key and send encrypted file" << std::endl;
        if (!myClient->encrypt_and_send_file())
            throw std::exception("Failed to encrypt and send file\n");
        
        std::cout << "Server has response with a valid CRC from the encrypted file!\n" << std::endl;

    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    std::cout << "THE END\n" << std::endl;

}
