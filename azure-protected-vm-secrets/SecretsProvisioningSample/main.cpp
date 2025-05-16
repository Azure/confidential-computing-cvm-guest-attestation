#include <iostream>
#include "SecretsProvisioningSample.h"

/*
* Main function
* commands are:
* - Create a key
* - Check if a key is present
* - Remove a key
* - Get the vmid
* - Encrypt data - takes in a string and encrypts it and prints a jwt
* - Decrypt data - takes in a jwt and decrypts it and prints the secret
*/
int main(int argc, char* argv[])
{
	if (argc < 2) {
		std::cout << "Please provide a command." << std::endl;
		return 1;
	}

	std::string command = argv[1];
	if (command == "Decrypt") {
		if (argc < 3) {
			std::cout << "Please provide a string to decrypt." << std::endl;
			return 1;
		}
		Decrypt(argv[2]);
	}
#ifndef DYNAMIC_SAMPLE
	else if (command == "GenerateKey") {
		GenerateKey();
	}
	else if (command == "IsKeyPresent") {
		if (IsKeyPresent()) {
			std::cout << "Key is present" << std::endl;
		}
		else {
			std::cout << "Key is not present" << std::endl;
		}
	}
	else if (command == "RemoveKey") {
		RemoveKey();
	}
	else if (command == "GetVmid") {
		GetVmidFromSmbios();
	}
	else if (command == "IsCvm") {
		IsCvm();
	}
	else if (command == "Encrypt") {
		if (argc < 3) {
			std::cout << "Please provide a string to encrypt." << std::endl;
			return 1;
		}
		std::string token = Encrypt(argv[2]);
		std::cout << "Token: " << token << std::endl;
	}
#endif
	else {
		std::cout << "Unknown command." << std::endl;
		return 1;
	}

	return 0;
}