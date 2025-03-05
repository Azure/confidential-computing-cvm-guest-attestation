// SecretsProvisioningSample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define UMDF_USING_NTSTATUS
#include <iostream>
#include "SecretsProvisioningLibrary.h"
#ifndef DYNAMIC_SAMPLE
#include "Tss2Wrapper.h"
#include "TpmError.h"
#include "AesWrapper.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslAesWrapper.h"
#include "Linux/OsslECDiffieHellman.h"
#include "Linux/OsslHKDF.h"
#include "Linux/OsslError.h"
#else
#include "Windows/BcryptAesWrapper.h"
#include "Windows/BcryptECDiffieHellman.h"
#include "Windows/BcryptHKDF.h"
#include "BcryptError.h"
#endif // PLATFORM_UNIX
// #include "ECDiffieHellman.h"
// #include "HKDF.h"
#include "JsonWebToken.h"
#include "System.h"
#include <nlohmann/json.hpp>

std::vector<BYTE> MakeRandomBytes(size_t a_Length)
{
    std::vector<BYTE> result(a_Length);
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = (BYTE)rand();
    }

    return result;
}
void GenerateKey() {
    std::unique_ptr<Tss2Wrapper> tss2Wrapper;
    try {
        tss2Wrapper = std::make_unique <Tss2Wrapper>();
        tss2Wrapper->GenerateGuestKey();
    }
    catch (TpmError e) {
        std::cout << "Error in TPM " << e.getTPMError() << std::endl;
    }
}


void RemoveKey() {
	std::unique_ptr<Tss2Wrapper> tss2Wrapper;
	try {
		tss2Wrapper = std::make_unique <Tss2Wrapper>();
		tss2Wrapper->RemoveKey();
	}
	catch (TpmError e) {
		std::cout << "Error in TPM " << e.getTPMError() << std::endl;
	}
}

bool IsKeyPresent() {
    std::unique_ptr<Tss2Wrapper> tss2Wrapper;
	bool isKeyPresent = false;
    try {
        tss2Wrapper = std::make_unique <Tss2Wrapper>();
        isKeyPresent = tss2Wrapper->IsKeyPresent();
        
    }
    catch (TpmError e) {
        std::cout << "Error in TPM " << e.getTPMError() << std::endl;
    }
	return isKeyPresent;
}

void GetVmidFromSmbios() {
    std::string uuid = GetSystemUuid();
    std::cout << "UUID: " << uuid << std::endl;
}

std::string Encrypt(const char* data) {
    std::vector<unsigned char> secretData(data, data + strlen(data) + 1);
    std::vector<unsigned char> ciphertextData;
    std::vector<unsigned char> wrappedAesKey;
    std::vector<unsigned char> encryptedSecret, encryptedEcdhPrivate;
    std::vector<unsigned char> dataNonce, wrappingNonce;
    std::unique_ptr<Tss2Wrapper> tss2Wrapper;
    std::unique_ptr<AesWrapper> aesWrapper;
    std::unique_ptr<AesCreator> aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;
    std::vector<unsigned char> wrappingKey, aesKey;
    std::vector<unsigned char> exportedPublicKeyData, exportedPrivateKeyData;
    std::vector<unsigned char> saltData = MakeRandomBytes(32);
    std::unique_ptr<JsonWebToken> jwt;
	std::string token;

    try {
        std::string infoString = GetSystemUuid();
        std::vector<unsigned char> infoData(infoString.begin(), infoString.end());

        // Generate ECDH key pair
#ifdef PLATFORM_UNIX
		std::unique_ptr<OsslECDiffieHellman> ecdhPrivate = std::make_unique<OsslECDiffieHellman>();
		std::unique_ptr<OsslECDiffieHellman> ecdhPublic = std::make_unique <OsslECDiffieHellman>();
#else
		std::unique_ptr<BcryptECDiffieHellman> ecdhPrivate = std::make_unique<BcryptECDiffieHellman>();
		std::unique_ptr<BcryptECDiffieHellman> ecdhPublic = std::make_unique<BcryptECDiffieHellman>();
#endif
        ecdhPrivate->GenerateKeyPair();
        ecdhPublic->GenerateKeyPair();
        exportedPublicKeyData = ecdhPublic->ExportSubjectPublicKeyInfo();
        exportedPrivateKeyData = ecdhPrivate->ExportPkcs8PrivateKey();

        // Derive shared secret
#ifdef PLATFORM_UNIX
        OsslHKDF hkdf = OsslHKDF(ecdhPrivate->DeriveSecret(*ecdhPublic));
#else
		BcryptHKDF hkdf = BcryptHKDF(ecdhPrivate->DeriveSecret(*ecdhPublic));
#endif
        aesKey = hkdf.DeriveKey(saltData, infoData, 32);
        if (aesKey.size() == 0) {
            std::cout << "Failed to derive key" << std::endl;
            return token;
        }
        std::cout << "Derived key size" << aesKey.size() << std::endl;

        // Prep AesWrapper
#ifdef PLATFORM_UNIX
		aesCreator = std::make_unique<OsslGcmCreator>();
#else
        aesCreator = std::make_unique<GcmCreator>();
#endif // PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();

        // Encrypt the secret data
        aesWrapper->SetKey(aesKey);
        dataNonce = MakeRandomBytes(12);
		aesChainingInfo = aesWrapper->SetChainingInfo(dataNonce);
		encryptedSecret = aesWrapper->Encrypt(secretData, aesChainingInfo.get());
		if (encryptedSecret.size() == 0) {
			std::cout << "Failed to encrypt data" << std::endl;
			return token;
		}
		std::cout << "Encrypted data size" << encryptedSecret.size() << std::endl;

		// Encrypt the private key
		std::vector<unsigned char> wrappingKey = MakeRandomBytes(32);
		aesWrapper->SetKey(wrappingKey);
		wrappingNonce = MakeRandomBytes(12);
		aesChainingInfo = aesWrapper->SetChainingInfo(wrappingNonce);
		encryptedEcdhPrivate = aesWrapper->Encrypt(exportedPrivateKeyData, aesChainingInfo.get());
		if (encryptedSecret.size() == 0) {
			std::cout << "Failed to encrypt data" << std::endl;
			return token;
		}

		// Encrypt AES key with EK
		tss2Wrapper = std::make_unique <Tss2Wrapper>();
		printf("Generated EK\nPreparing to encrypt\n");
		wrappedAesKey = tss2Wrapper->Tss2RsaEncrypt(wrappingKey);
		if (wrappedAesKey.size() == 0) {
			std::cout << "Failed to wrap key" << std::endl;
			return token;
		}

	}
	catch (TpmError e) {
		std::cout << "Error in TPM " << e.getTPMError() << std::endl;
		return token;
	}
#ifndef PLATFORM_UNIX
	catch (BcryptError e) {
		std::cout << "Error in Bcrypt " << e.getErrorInfo() << std::endl;
		return token;
	}
#else
	catch (OsslError e) {
		std::cout << "Error in Ossl " << e.getErrorInfo() << std::endl;
		return token;
	}
#endif // !PLATFORM_UNIX
	catch (std::exception e) {
		std::cout << "Failed to encrypt data" << e.what() << std::endl;
		return token;
	}
	// Prepare jwt
	jwt = std::make_unique<JsonWebToken>();
	json header = {
		{"alg", "RS256"},
		{"typ", "JWT"}
	};
	jwt->SetHeader(header);
	json payload = {
		{"salt", encoders::base64_encode(saltData)},
		{"dataNonce", encoders::base64_encode(dataNonce)},
		{"keyNonce", encoders::base64_encode(wrappingNonce)},
		{"wrappedAesTransportKey", encoders::base64_encode(wrappedAesKey)},
		{"encryptedSecret", encoders::base64_encode(encryptedSecret)},
		{"encryptedGuestEcdhPrivateKey", encoders::base64_encode(encryptedEcdhPrivate)},
		{"ephemeralEcdhPublicKey", encoders::base64_encode(exportedPublicKeyData)}
	};
	jwt->SetPayload(payload);
	token = jwt->CreateToken();
	return token;
}
#endif

std::string Decrypt(const char* jwt) {
	std::string secret;
    char* output_secret = nullptr;
    int jwtlen = strlen(jwt); // hacky way to get the length of the jwt
	long result = unprotect_secret((char*)(jwt), jwtlen, &output_secret);
	if (result <= 0) {
		std::cout << "Failed to unprotect secret" << std::hex << result << std::endl;
		return secret;
	}
	if (output_secret != nullptr) {
		secret = std::string(output_secret, result);
		std::cout << "\n\nSecret: " << secret.c_str() << std::endl;
		free_secret(output_secret);
	}
	return secret;
}

