// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//SecretsProvisioningLibrary.cpp : Defines the functions for the static library.
//
#define WIN32_LEAN_AND_MEAN
#include "pch.h"
#include <memory>
#include <vector>
#include <iostream>

#include "LibraryLogger.h"
#include "TpmError.h"
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
#include "AesWrapper.h"
#include "HclReportParser.h"
#include "Tpm.h"
#include "Tss2LogController.h"
#include "JsonWebToken.h"
#include "Policy.h"
#include "System.h"

using namespace SecretsLogger;

std::vector<unsigned char> decrypt_secret(json claims) {
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

	try
	{
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
			LIBSECRETS_LOG(LogLevel::Error, "TPM Decrypt\n", "ptext len %d", aesKey.size());
			return aesKey;
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
			LIBSECRETS_LOG(LogLevel::Error, "Decrypt ECDH Private returned empty\n", "encodedEcdhPrivate.size() == 0");
			return encodedEcdhPrivate;
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
		return plaintextData;
	}
	catch (...) {
		LIBSECRETS_LOG(LogLevel::Error, "Exception in Decryption\n", "An error occurred during decryption");
		throw;
	}
}

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// See header file for function description
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
long unprotect_secret(char* jwt, unsigned int jwtlen, unsigned int policy, char** output_secret, unsigned int* eval_policy) {
	// Check if the policy is valid
	PolicyEvaluator pe(static_cast<PolicyOption>(policy), std::string(jwt, jwtlen));
	std::vector<unsigned char> plaintextData;
	std::unique_ptr<char[]> inOutputSecret;
	long result = 0;

	*eval_policy = static_cast<unsigned int>(pe.GetEvaluatedPolicy());
	if (!pe.IsCompliant()) {
		LIBSECRETS_LOG(LogLevel::Error, "Unprotect Secret\n", "Invalid policy %d does not match evaluated settings %d", policy, *eval_policy);
		return (long)ErrorCode::PolicyMismatchError; // return error code for policy mismatch
	}
	if (pe.IsLegacy()) {
		plaintextData = pe.GetLegacyString();
	}
	else {
		json claims = pe.GetClaims();
		try {
			plaintextData = decrypt_secret(claims);
			if (plaintextData.size() == 0) {
				LIBSECRETS_LOG(LogLevel::Error, "Unprotect Secret\n", "Decrypted data is 0 Length");
				return LONG_MIN;
			}
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
	}
	// Marshal to C string
	inOutputSecret = std::make_unique<char[]>(plaintextData.size());
	if (inOutputSecret == nullptr) {
		LIBSECRETS_LOG(LogLevel::Warning, "Unprotect Secret\n", "Pointer allocation failed");
		return LONG_MIN;
	}

	if (result == 0) {
		// Successful decryption, copy the data to output_secret
		std::copy(plaintextData.begin(), plaintextData.end(), inOutputSecret.get());
		*output_secret = inOutputSecret.release();
		result = static_cast<long>(plaintextData.size());
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

#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
bool is_cvm() {
	Tss2LogController logController = Tss2LogController::SuppressAllLogs();
	Tpm tpm{};
	try {
		std::vector<unsigned char> hclReport = tpm.ReadHclReport();
		if (hclReport.size() == 0) {
			LIBSECRETS_LOG(LogLevel::Debug, "TPM Read HCL Report", "HCL Report is 0 Length");
			return false;
		}
		LIBSECRETS_LOG(LogLevel::Debug, "Completed Read HCL Report", "HCL Report size is : %d", hclReport.size());
		HclReportParser hclReportParser;
		if (hclReportParser.IsValidHclReport(hclReport)) {
			LIBSECRETS_LOG(LogLevel::Debug, "Parse HCL Report", "HCL Report is valid");
			return true;
		}
		else {
			LIBSECRETS_LOG(LogLevel::Debug, "Parse HCL Report", "HCL Report is not valid");
			return false;
		}
	}
	catch (TpmError err) {
		ErrorCode lib_rc = err.GetLibRC();
		if (lib_rc == ErrorCode::TpmError_Handles_handlePresentError)
		{
			// If the TPM handle is not present, it is not a CVM
			LIBSECRETS_LOG(LogLevel::Debug, "TPM Read HCL Report", "TPM handle not present, not a CVM");
			return false;
		}
		LIBSECRETS_LOG(LogLevel::Error, "TPM Read HCL Report", "TPM error 0x%x occurred\n Description %s",
			err.getReturnCode(), err.getTPMError());
		return false;
	}
}

#ifdef __cplusplus
}
#endif // __cplusplus