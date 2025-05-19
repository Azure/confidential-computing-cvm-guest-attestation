// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#ifndef PLATFORM_UNIX
#define UMDF_USING_NTSTATUS
#include <windows.h>
#include "BcryptError.h"
#endif
#include "AesWrapper.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslAesWrapper.h"
#include "Linux/OsslError.h"
#include "Linux/OsslECDiffieHellman.h"
#include "Linux/OsslHKDF.h"
#else
#include "Windows/BcryptAesWrapper.h"
#include "Windows/BcryptECDiffieHellman.h"
#include "Windows/BcryptHKDF.h"
#endif // PLATFORM_UNIX

// Unit test for AesWrapper
TEST(AesWrapperTest, ConstructorTest)
{
    // Test that the constructor initializes the AesWrapper object
    std::unique_ptr<AesWrapper>  aesWrapper;
    std::unique_ptr<AesCreator>  aesCreator;
    try {
#ifndef PLATFORM_UNIX
        aesCreator = std::make_unique<GcmCreator>();
#else
        aesCreator = std::make_unique<OsslGcmCreator>();
#endif // !PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();
        ASSERT_NE(aesWrapper, nullptr);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
}

TEST(AesWrapperTest, AesEncryptDecryptTest)
{
    std::vector<unsigned char> decryptedData;
    std::vector<unsigned char> plaintextData(121, 0x01);
    std::vector<unsigned char> encryptedData;
    std::unique_ptr<AesWrapper>  aesWrapper, decryptAesWrapper;
    std::unique_ptr<AesCreator>  aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;


    // Test the AesEncrypt method
    try {
#ifdef PLATFORM_UNIX
        aesCreator = std::make_unique<OsslGcmCreator>();
#else
        aesCreator = std::make_unique<GcmCreator>();
#endif // PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();
        decryptAesWrapper= aesCreator->CreateAesWrapper();
        std::vector<unsigned char> key(32, 0);
        aesWrapper->SetKey(key);
        aesChainingInfo = aesWrapper->SetChainingInfo(std::vector<unsigned char>(12, 0));
        encryptedData = aesWrapper->Encrypt(plaintextData, aesChainingInfo.get());
        // Explicitly delete as we reset the pointer
        delete aesChainingInfo.release();
        decryptAesWrapper->SetKey(key);
        aesChainingInfo = decryptAesWrapper->SetChainingInfo(std::vector<unsigned char>(12, 0));
        decryptedData = decryptAesWrapper->Decrypt(encryptedData, aesChainingInfo.get());
    }
#ifndef PLATFORM_UNIX
    catch (BcryptError e) {
        printf("Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
            e.getStatusCode(), e.what(), e.getErrorInfo());
    }
#else
	catch (OsslError err) {
        printf("Openssl Error\n Message %s\t Bcrypt Info%s",
			err.what(), err.getErrorInfo());
	}
#endif
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    ASSERT_EQ(encryptedData.size(), plaintextData.size() + 16);
    ASSERT_EQ(decryptedData.size(), plaintextData.size());
    ASSERT_EQ(decryptedData, plaintextData);
}

TEST(AesWrapperTest, AesEncryptTestFail)
{
    std::vector<unsigned char> decryptedData;
    std::vector<unsigned char> plaintextData = { 0x01, 0x02, 0x03, 0x04 };
    std::vector<unsigned char> encryptedData;
    std::unique_ptr<AesWrapper>  aesWrapper;
    std::unique_ptr<AesCreator>  aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;
    std::vector<unsigned char> key(16, 0);

#ifdef PLATFORM_UNIX
    aesCreator = std::make_unique<OsslGcmCreator>();
#else
    aesCreator = std::make_unique<GcmCreator>();
#endif // PLATFORM_UNIX
    aesWrapper = aesCreator->CreateAesWrapper();
    aesWrapper->SetKey(key);

    // Test the AesDecrypt method
    EXPECT_THROW( {
        encryptedData = aesWrapper->Encrypt(plaintextData, nullptr);
    }, std::exception);   
}

TEST(AesWrapperTest, AesDecryptTestFail)
{
    std::vector<unsigned char> decryptedData;
    std::vector<unsigned char> plaintextData = { 0x01, 0x02, 0x03, 0x04 };
    std::vector<unsigned char> encryptedData;
    std::unique_ptr<AesWrapper>  aesWrapper;
    std::unique_ptr<AesCreator>  aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;
    std::vector<unsigned char> key(16, 0);

    try {
#ifdef PLATFORM_UNIX
        aesCreator = std::make_unique<OsslGcmCreator>();
#else
        aesCreator = std::make_unique<GcmCreator>();
#endif // PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();
        aesWrapper->SetKey(key);
        aesChainingInfo = aesWrapper->SetChainingInfo(std::vector<unsigned char>(12, 0));
        encryptedData = aesWrapper->Encrypt(plaintextData, aesChainingInfo.get());
    }
#ifndef PLATFORM_UNIX
    catch (BcryptError e) {
        printf("Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
            e.getStatusCode(), e.what(), e.getErrorInfo());
    }
#endif
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    // Test the AesDecrypt method. Expected fail as the chaining info is nullptr.
    EXPECT_THROW({
        decryptedData = aesWrapper->Decrypt(encryptedData, nullptr);
    }, std::exception);
}


TEST(AesWrapperTest, AesDecryptMacFail)
{
    std::vector<unsigned char> decryptedData;
    std::vector<unsigned char> plaintextData = { 0x01, 0x02, 0x03, 0x04 };
    std::vector<unsigned char> encryptedData;
    std::unique_ptr<AesWrapper>  aesWrapper;
    std::unique_ptr<AesCreator>  aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;
    std::vector<unsigned char> key(16, 0);

    try {
#ifdef PLATFORM_UNIX
        aesCreator = std::make_unique<OsslGcmCreator>();
#else
        aesCreator = std::make_unique<GcmCreator>();
#endif // PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();
        aesWrapper->SetKey(key);
        aesChainingInfo = aesWrapper->SetChainingInfo(std::vector<unsigned char>(12, 0));
        encryptedData = aesWrapper->Encrypt(plaintextData, aesChainingInfo.get());
        // Explicitly delete as we reset the pointer
        delete aesChainingInfo.release();
    }
#ifndef PLATFORM_UNIX
    catch (BcryptError e) {
        printf("Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
            e.getStatusCode(), e.what(), e.getErrorInfo());
    }
#endif
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    // Modify the Mac
    encryptedData[encryptedData.size() - 1] = 0x00;

    aesChainingInfo = aesWrapper->SetChainingInfo(std::vector<unsigned char>(12, 0));

    // Test the AesDecrypt method. Expect a BcryptError.
#ifdef PLATFORM_UNIX
    EXPECT_THROW({
        decryptedData = aesWrapper->Decrypt(encryptedData, aesChainingInfo.get());
    }, std::exception);
#else
    EXPECT_THROW({
        decryptedData = aesWrapper->Decrypt(encryptedData, aesChainingInfo.get());
    }, BcryptError);
#endif
}

// Unit test for ECDiffieHellman
TEST(ECDiffieHellmanTest, ConstructorTest)
{
	// Test that the constructor initializes the ECDiffieHellman object
	try {
#ifndef PLATFORM_UNIX
        std::unique_ptr<BcryptECDiffieHellman>  ecDiffieHellman;
		ecDiffieHellman = std::make_unique<BcryptECDiffieHellman>();
#else
        std::unique_ptr<OsslECDiffieHellman>  ecDiffieHellman;
        ecDiffieHellman = std::make_unique<OsslECDiffieHellman>();
#endif // !PLATFORM_UNIX
		ASSERT_NE(ecDiffieHellman, nullptr);
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}

TEST(ECDiffieHellmanTest, ImportExportTest)
{
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslECDiffieHellman>  ecDiffieHellmanA, ecDiffieHellmanB, importKeyA, imporKeyB;
#else
	std::unique_ptr<BcryptECDiffieHellman>  ecDiffieHellmanA, ecDiffieHellmanB, importKeyA, imporKeyB;
#endif // PLATFORM_UNIX


	// Test the GenerateKeyPair method
	try {
#ifdef PLATFORM_UNIX
		ecDiffieHellmanA = std::make_unique<OsslECDiffieHellman>();
		ecDiffieHellmanB = std::make_unique<OsslECDiffieHellman>();
		importKeyA = std::make_unique<OsslECDiffieHellman>();
		imporKeyB = std::make_unique<OsslECDiffieHellman>();
#else
		ecDiffieHellmanA = std::make_unique<BcryptECDiffieHellman>();
		ecDiffieHellmanB = std::make_unique<BcryptECDiffieHellman>();
		importKeyA = std::make_unique<BcryptECDiffieHellman>();
		imporKeyB = std::make_unique<BcryptECDiffieHellman>();
#endif // PLATFORM_UNIX
		ecDiffieHellmanA->GenerateKeyPair();
		ecDiffieHellmanB->GenerateKeyPair();
		publicKey = ecDiffieHellmanA->ExportSubjectPublicKeyInfo();
		privateKey = ecDiffieHellmanB->ExportPkcs8PrivateKey();
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}

	ASSERT_NO_THROW(
		importKeyA->ImportSubjectPublicKeyInfo(publicKey);
		imporKeyB->ImportPkcs8PrivateKey(privateKey);
	);
}

TEST(ECDiffieHellmanTest, KeyGenTest)
{
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
    std::vector<unsigned char> testKDFInput = std::vector<unsigned char>(16, 0);
	std::vector<unsigned char> derivedSecretA, derivedSecretB;
#ifdef PLATFORM_UNIX
    std::unique_ptr<OsslECDiffieHellman>  ecDiffieHellmanA, ecDiffieHellmanB, importKeyA, importKeyB;
	std::unique_ptr<OsslHKDF> hkdfA, hkdfB;
    std::vector<unsigned char> secretA, secretB;
#else
	std::unique_ptr<BcryptECDiffieHellman>  ecDiffieHellmanA, ecDiffieHellmanB, importKeyA, importKeyB;
	std::unique_ptr<BcryptHKDF> hkdfA, hkdfB;
	BCRYPT_SECRET_HANDLE secretA, secretB;
#endif // PLATFORM_UNIX

	// Test the GenerateKeyPair method
	try {
#ifdef PLATFORM_UNIX
		ecDiffieHellmanA = std::make_unique<OsslECDiffieHellman>();
		ecDiffieHellmanB = std::make_unique<OsslECDiffieHellman>();
		importKeyA = std::make_unique<OsslECDiffieHellman>();
		importKeyB = std::make_unique<OsslECDiffieHellman>();
#else
		ecDiffieHellmanA = std::make_unique<BcryptECDiffieHellman>();
		ecDiffieHellmanB = std::make_unique<BcryptECDiffieHellman>();
		importKeyA = std::make_unique<BcryptECDiffieHellman>();
		importKeyB = std::make_unique<BcryptECDiffieHellman>();
#endif // PLATFORM_UNIX
		ecDiffieHellmanA->GenerateKeyPair();
		ecDiffieHellmanB->GenerateKeyPair();
		publicKey = ecDiffieHellmanA->ExportSubjectPublicKeyInfo();
		privateKey = ecDiffieHellmanB->ExportPkcs8PrivateKey();
		importKeyA->ImportSubjectPublicKeyInfo(publicKey);
		importKeyB->ImportPkcs8PrivateKey(privateKey);
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
#ifdef PLATFORM_UNIX
	ASSERT_NO_THROW(
		secretA = ecDiffieHellmanA->DeriveSecret(*ecDiffieHellmanB);
		secretB = importKeyB->DeriveSecret(*importKeyA);
        hkdfA = std::make_unique<OsslHKDF>(secretA);
        hkdfB = std::make_unique<OsslHKDF>(secretB);
		derivedSecretA = hkdfA->DeriveKey(testKDFInput, testKDFInput, 32);
		derivedSecretB = hkdfB->DeriveKey(testKDFInput, testKDFInput, 32);
	);
    ASSERT_EQ(secretA, secretB);
#else
    ASSERT_NO_THROW(
        secretA = ecDiffieHellmanA->DeriveSecret(*ecDiffieHellmanB);
        secretB = importKeyB->DeriveSecret(*importKeyA);
        hkdfA = std::make_unique<BcryptHKDF>(secretA);
        hkdfB = std::make_unique<BcryptHKDF>(secretB);
        derivedSecretA = hkdfA->DeriveKey(testKDFInput, testKDFInput, 32);
        derivedSecretB = hkdfB->DeriveKey(testKDFInput, testKDFInput, 32);
    );
#endif // PLATFORM_UNIX
    ASSERT_EQ(derivedSecretA.size(), 32);
    ASSERT_EQ(derivedSecretB.size(), 32);
	ASSERT_EQ(derivedSecretA, derivedSecretB);
}
