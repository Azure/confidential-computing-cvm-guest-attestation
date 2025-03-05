//SecretsProvisioningLibrary.cpp : Defines the functions for the static library.
//
#define WIN32_LEAN_AND_MEAN
#include "pch.h"
#include <memory>
#include <vector>
#include <iostream>

#include "LibraryLogger.h"
#include "TpmError.h"
#ifndef PLATFORM_UNIX
#include "BcryptError.h"
#endif // !PLATFORM_UNIX
#include "AesWrapper.h"
#include "Tpm.h"
#include "JsonWebToken.h"
#include "System.h"
#ifdef PLATFORM_UNIX
#include "Linux/OsslAesWrapper.h"
#include "Linux/OsslECDiffieHellman.h"
#include "Linux/OsslHKDF.h"
#include "Linux/OsslError.h"
#else
#include "Windows/BcryptAesWrapper.h"
#include "Windows/BcryptECDiffieHellman.h"
#include "Windows/BcryptHKDF.h"
#endif // PLATFORM_UNIX



#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

using namespace SecretsLogger;

// See header file for function description
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
long unprotect_secret(char* jwt, unsigned int jwtlen, char** output_secret) {
	std::unique_ptr<char*> inOutputSecret;
	long result = 0;
    std::unique_ptr<AesWrapper> aesWrapper;
    std::unique_ptr<AesCreator> aesCreator;
    std::unique_ptr<AesChainingInfo>  aesChainingInfo;
	std::unique_ptr<JsonWebToken> jwtObj;
	std::vector<unsigned char> salt;
	std::vector<unsigned char> dataNonce;
	std::vector<unsigned char> wrappingNonce;
	std::vector<unsigned char> wrappedAesKey;
	std::vector<unsigned char> encryptedSecret;
	std::vector<unsigned char> encryptedEcdhPrivate;
	std::vector<unsigned char> exportedPublicKeyData;

	std::string infoString = GetSystemUuid();
	std::vector<unsigned char> infoData(infoString.begin(), infoString.end());

    std::string jwtStr(jwt, jwt + jwtlen);
    LIBSECRETS_LOG(LogLevel::Debug, "Unprotect Secret\n", "JWT %s", jwtStr.c_str());
    jwtObj = std::make_unique<JsonWebToken>();
    
	try {
        // Parse the JWT
		jwtObj->ParseToken(jwtStr, true);
		json claims = jwtObj->getClaims();

		LIBSECRETS_LOG(LogLevel::Debug, "Unprotect Secret\n", "JWT claims\n %s", claims.dump(4).c_str());

		salt = encoders::base64_decode(claims["salt"]);
		dataNonce = encoders::base64_decode(claims["dataNonce"]);
		wrappingNonce = encoders::base64_decode(claims["keyNonce"]);
		wrappedAesKey = encoders::base64_decode(claims["wrappedAesTransportKey"]);
		encryptedSecret = encoders::base64_decode(claims["encryptedSecret"]);
		encryptedEcdhPrivate = encoders::base64_decode(claims["encryptedGuestEcdhPrivateKey"]);
		exportedPublicKeyData = encoders::base64_decode(claims["ephemeralEcdhPublicKey"]);
		Tpm tpm{};
		std::vector<unsigned char> aesKey = tpm.RsaDecrypt(wrappedAesKey);
		if (aesKey.size() == 0) {
			printf("Failed to decrypt data\n");
			result = LONG_MIN;
			return result;
		}

#ifndef PLATFORM_UNIX
        aesCreator = std::make_unique<GcmCreator>();
#else
		aesCreator = std::make_unique<OsslGcmCreator>();
#endif // !PLATFORM_UNIX
        aesWrapper = aesCreator->CreateAesWrapper();
        aesWrapper->SetKey(aesKey);
        aesChainingInfo = aesWrapper->SetChainingInfo(wrappingNonce);
		std::vector<unsigned char> encodedEcdhPrivate = aesWrapper->Decrypt(encryptedEcdhPrivate, aesChainingInfo.get());
		if (encodedEcdhPrivate.size() == 0) {
			LIBSECRETS_LOG(LogLevel::Error, "TPM Decrypt\n", "ptext len %d", encodedEcdhPrivate.size());
			result = LONG_MIN;
			return result;
		}

		// Import ECDH keys
#ifdef PLATFORM_UNIX
		std::unique_ptr<OsslECDiffieHellman> ecdhPrivate = std::make_unique<OsslECDiffieHellman>();
		std::unique_ptr<OsslECDiffieHellman> ecdhPublic = std::make_unique<OsslECDiffieHellman>();
#else
		std::unique_ptr<BcryptECDiffieHellman> ecdhPrivate = std::make_unique<BcryptECDiffieHellman>();
		std::unique_ptr<BcryptECDiffieHellman> ecdhPublic = std::make_unique<BcryptECDiffieHellman>();
#endif
		ecdhPrivate->ImportPkcs8PrivateKey(encodedEcdhPrivate);
		ecdhPublic->ImportSubjectPublicKeyInfo(exportedPublicKeyData);

		// Derive shared secret
#ifdef PLATFORM_UNIX
		std::unique_ptr <OsslHKDF> hkdf = std::make_unique<OsslHKDF>(ecdhPrivate->DeriveSecret(*ecdhPublic));
#else
		std::unique_ptr <BcryptHKDF> hkdf = std::make_unique<BcryptHKDF>(ecdhPrivate->DeriveSecret(*ecdhPublic));
#endif
		aesKey = hkdf->DeriveKey(salt, infoData, 32);

		// Decrypt the secret
		aesWrapper->SetKey(aesKey);
        aesChainingInfo = aesWrapper->SetChainingInfo(dataNonce);
		std::vector<unsigned char> plaintextData = aesWrapper->Decrypt(encryptedSecret, aesChainingInfo.get());

		// Marshal to C string
		std::unique_ptr<char[]> inOutputSecret(new char[plaintextData.size()]);
		if (inOutputSecret == nullptr) {
			LIBSECRETS_LOG(LogLevel::Warning, "Unprotect Secret\n", "Pointer allocation failed");
			return LONG_MIN;
		}
		std::copy(plaintextData.begin(), plaintextData.end(), inOutputSecret.get());
		*output_secret = inOutputSecret.release();
		result = static_cast<long>(plaintextData.size());
	}
	catch (TpmError err) {
		LIBSECRETS_LOG(LogLevel::Error, "TPM Decrypt\n",
			"TPM error 0x%x occurred\n Description %s",
			err.getReturnCode(), err.getTPMError());
		result = (long)err.GetLibRC();
	}
#ifndef PLATFORM_UNIX
    catch (BcryptError err) {
        LIBSECRETS_LOG(LogLevel::Error, "Bcrypt Decrypt\n",
            "Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
            err.getStatusCode(), err.what(), err.getErrorInfo());
        result = (long)err.GetLibRC();
    }
	catch (WinCryptError err) {
		LIBSECRETS_LOG(LogLevel::Error, "WinCrypt Decode\n",
			"Message %s\t Bcrypt Info%s",
			err.what(), err.GetErrorMessage());
		result = (long)err.GetLibRC();
	}
#else
	catch (OsslError err) {
		LIBSECRETS_LOG(LogLevel::Error, "Openssl Decode\n",
			"Message %s\t Openssl Info%s",
			err.what(), err.getErrorInfo());
		result = (long)ErrorCode::CryptographyError;
	}
#endif // !PLATFORM_UNIX
	catch (JwtError err) {
		LIBSECRETS_LOG(LogLevel::Error, "JWT Validation\n",
			"JWT error occurred\n Message %s",
			err.what());
		result = (long)err.GetLibRC();
	}
    catch (std::runtime_error e) {
        LIBSECRETS_LOG(LogLevel::Error, "runtime Exception\n", "error info %s", e.what());
        result = LONG_MIN;
    }
    catch (std::exception e) {
        LIBSECRETS_LOG(LogLevel::Error, "Standard Exception\n", "error info %s", e.what());
        result = LONG_MIN;
    }
        
    return result;
}

#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
void free_secret(char* secret) {
	if (secret != nullptr)
		delete[] secret;
}

#ifdef __cplusplus
}
#endif // __cplusplus