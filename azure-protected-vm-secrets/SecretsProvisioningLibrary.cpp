// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//SecretsProvisioningLibrary.cpp : Defines the functions for the static library.
//
#define WIN32_LEAN_AND_MEAN
#include <memory>
#include <vector>
#include <iostream>

#include "CvmHelper/inc/CvmHelper.h"

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
#include "Version.h"

using namespace SecretsLogger;

static long decrypt_secret(const json& claims, std::vector<unsigned char>& plaintextData) {
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
    std::string str_claims;

    try
	{
		// Log the claims and VMID for debugging
        LIBSECRETS_LOG(LogLevel::Info, "Unprotect Secret\n", "\tVmid: %s\n", infoString.c_str());
        str_claims = claims.dump(4);

        // Extract fields from JWT

		salt = encoders::base64_decode(claims.at("salt"));
		dataNonce = encoders::base64_decode(claims.at("dataNonce"));
		wrappingNonce = encoders::base64_decode(claims.at("keyNonce"));
		wrappedAesKey = encoders::base64_decode(claims.at("wrappedAesTransportKey"));
		encryptedSecret = encoders::base64_decode(claims.at("encryptedSecret"));
		encryptedEcdhPrivate = encoders::base64_decode(claims.at("encryptedGuestEcdhPrivateKey"));
		exportedPublicKeyData = encoders::base64_decode(claims.at("ephemeralEcdhPublicKey"));
		Tpm tpm{};
		std::vector<unsigned char> aesKey = tpm.RsaDecrypt(wrappedAesKey);
		if (aesKey.size() == 0) {
			LIBSECRETS_LOG(LogLevel::Error, "TPM Decrypt\n",
                "JWT claims\n%s\nptext len %d\n",
                str_claims.c_str(), aesKey.size());
			return (long)ErrorCode::UnknownError;
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
        if (encodedEcdhPrivate.size() == 0)
        {
            LIBSECRETS_LOG(LogLevel::Error, "Decrypt ECDH Private returned empty\n",
                "JWT claims\n%s\nencodedEcdhPrivate.size() == 0\n",
                str_claims.c_str());
			return (long)ErrorCode::UnknownError;
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
		plaintextData = aesWrapper->Decrypt(encryptedSecret, aesChainingInfo.get());
        if (plaintextData.size() == 0) {
            LIBSECRETS_LOG(LogLevel::Error, "Final Decryption\n",
                "Secret decryption failed - empty result\nJWT claims\n%s\n",
                str_claims.c_str());
            return (long)ErrorCode::UnknownError;
        }

        return 0; // Success
    }
    catch (TpmError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "TPM Decrypt\n",
            "TPM error 0x%x occurred\n Description %s\nJWT claims\n%s\n",
            err.getReturnCode(), err.getTPMError(), str_claims.c_str());
        return (long)err.GetLibRC();
    }
#ifndef PLATFORM_UNIX
    catch (BcryptError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "Bcrypt Decrypt\n",
            "JWT claims\n%s\nBcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s\n",
            str_claims.c_str(), err.getStatusCode(), err.what(), err.getErrorInfo());
        return (long)err.GetLibRC();
    }
    catch (WinCryptError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "WinCrypt Decode\n",
            "JWT claims\n%s\nMessage %s\t Bcrypt Info%s\n",
            str_claims.c_str(), err.what(), err.GetErrorMessage());
        return (long)err.GetLibRC();
    }
#else
    catch (OsslError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "Openssl Decode\n",
            "JWT claims\n%s\nMessage %s\t Openssl Info%s\n",
            str_claims.c_str(), err.what(), err.getErrorInfo());
        return (long)ErrorCode::CryptographyError;
    }
#endif
	catch (std::out_of_range& err) {
		LIBSECRETS_LOG(LogLevel::Error, "JWT Field Access\n",
			"Missing required JWT field: %s\n", err.what());
		return (long)ErrorCode::ParsingError_Jwt_missingFieldError;
	}
    catch (nlohmann::json::out_of_range& err) {
        LIBSECRETS_LOG(LogLevel::Error, "JWT Field Access\n",
            "Missing required JWT field: %s\n", err.what());
        return (long)ErrorCode::ParsingError_Jwt_missingFieldError;
    }
    catch (nlohmann::json::type_error& err) {
        LIBSECRETS_LOG(LogLevel::Error, "JWT Field Type\n",
            "Invalid JWT field type: %s\n", err.what());
        return (long)ErrorCode::ParsingError_Jwt_invalidFieldError;
    }
    catch (JwtError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "JWT Validation\n",
            "JWT error occurred\n Message %s\n",
            err.what());
        return (long)err.GetLibRC();
    }
    catch (std::runtime_error& e) {
        LIBSECRETS_LOG(LogLevel::Error, "Runtime Exception\n", "Error info: %s\n", e.what());
        return (long)ErrorCode::UnknownError;
    }
    catch (std::exception& e) {
        LIBSECRETS_LOG(LogLevel::Error, "Standard Exception\n", "Error info: %s\n", e.what());
        return (long)ErrorCode::UnknownError;
    }
    catch (...) {
        LIBSECRETS_LOG(LogLevel::Error, "Unknown Exception\n",
            "An unknown error occurred during decryption\nJWT claims\n%s\n",
            str_claims.c_str());
        return (long)ErrorCode::UnknownError;
    }
}

// Helper for buffer allocation and transfer
template<typename T>
static long marshal_output(const std::vector<T>& data, T** output) {
    if (data.empty()) {
        *output = nullptr;
        return 0;
    }
    
    auto buffer = std::make_unique<T[]>(data.size());
    if (!buffer) {
        LIBSECRETS_LOG(LogLevel::Warning, "Buffer Allocation\n", "Memory allocation failed\n");
        return (long)ErrorCode::UnknownError;
    }
    
    std::copy(data.begin(), data.end(), buffer.get());
    *output = buffer.release();
    return static_cast<long>(data.size());
}

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// See header file for function description
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
long unprotect_secret(char* jwt, unsigned int jwtlen, unsigned int policy, char** output_secret, unsigned int* eval_policy) {
    *output_secret = nullptr;

	LIBSECRETS_LOG(LogLevel::Info, "Unprotect Secret\n", "Starting unprotect_secret from library version %s with policy %d for input\n", secrets_library_version(), policy);

	try {
		// Policy evaluation
		PolicyEvaluator pe(static_cast<PolicyOption>(policy), jwt, jwtlen);
		
		*eval_policy = static_cast<unsigned int>(pe.GetEvaluatedPolicy());
		if (!pe.IsCompliant()) {
			LIBSECRETS_LOG(LogLevel::Error, "Unprotect Secret\n", 
						"Invalid policy %d does not match evaluated settings %d\n", policy, *eval_policy);
			return (long)ErrorCode::PolicyMismatchError;
		}

		// Get data
		std::vector<unsigned char> data;
		
		if (pe.IsLegacy()) {
			// Direct copy of input for legacy data
			data.assign(jwt, jwt + jwtlen);
		} else {
			// Decrypt JWT data
			json claims = pe.GetClaims();
			long result = decrypt_secret(claims, data);
			if (result != 0) {
				return result;
			}
		}
		return marshal_output(data, reinterpret_cast<unsigned char**>(output_secret));
	}
	catch (JwtError& err) {
		LIBSECRETS_LOG(LogLevel::Error, "Policy Evaluation", 
					   "Policy evaluation failed: %s\n", err.what());
		return (long)err.GetLibRC();
	}
	catch (std::exception& e) {
		LIBSECRETS_LOG(LogLevel::Error, "Exception", 
					   "Unexpected exception: %s\n", e.what());
		return (long)ErrorCode::UnknownError;
	}
	catch (...) {
		LIBSECRETS_LOG(LogLevel::Error, "API Exception", "Unknown exception occurred\n");
		return (long)ErrorCode::UnknownError;
	}
}

// See header file for function description
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
long unprotect_secret_wide(wchar_t* jwt, unsigned int jwtlen, unsigned int policy, wchar_t** output_secret, unsigned int* eval_policy) {
    *output_secret = nullptr;
	LIBSECRETS_LOG(LogLevel::Info, "Unprotect Secret\n", "Starting unprotect_secret_wide from library version %s with policy %d for input\n", secrets_library_version(), policy);

    try {
        // Policy evaluation
        PolicyEvaluator pe(static_cast<PolicyOption>(policy), jwt, jwtlen);
        
        *eval_policy = static_cast<unsigned int>(pe.GetEvaluatedPolicy());
        if (!pe.IsCompliant()) {
            LIBSECRETS_LOG(LogLevel::Error, "Unprotect Secret\n", 
                           "Invalid policy %d does not match evaluated settings %d\n", policy, *eval_policy);
            return (long)ErrorCode::PolicyMismatchError;
        }
        
        // Get wide character data
        std::vector<wchar_t> wide_data;
        
        if (pe.IsLegacy()) {
            // Direct copy of input for legacy data
            wide_data.assign(jwt, jwt + jwtlen);
        } else {
            // Decrypt and convert to wide characters
            json claims = pe.GetClaims();
            std::vector<unsigned char> plaintextData;
            
            long result = decrypt_secret(claims, plaintextData);
            if (result != 0) {
                return result;
            }
            
            // Convert to wide characters
            wide_data = utf8_sanitizer::utf8_to_wide(plaintextData);
            
            if (wide_data.empty() && !plaintextData.empty()) {
                LIBSECRETS_LOG(LogLevel::Error, "UTF-8 Conversion", 
                               "Failed to convert decrypted data to wide characters");
                return (long)ErrorCode::ParsingError_Jwt_invalidFieldError;
            }
        }
        
        return marshal_output(wide_data, output_secret);
        
    } catch (JwtError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "Wide API Policy Evaluation", 
                       "Policy evaluation failed: %s", err.what());
        return (long)err.GetLibRC();
    } catch (std::exception& e) {
        LIBSECRETS_LOG(LogLevel::Error, "Wide API Exception", 
                       "Unexpected exception: %s", e.what());
		return (long)ErrorCode::UnknownError;
    }
	catch (...) {
		LIBSECRETS_LOG(LogLevel::Error, "Wide API Exception", "Unknown exception occurred");
		return (long)ErrorCode::UnknownError;
	}
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
void free_secret_wide(wchar_t* secret) {
	if (secret != nullptr)
		delete[] secret;
}

#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
const char* get_error_message(long error_code) {
	if (error_code >= 0) {
		return error_code_name(ErrorCode::Success);
	} else {
		// Convert the long to the enum value
		ErrorCode code = static_cast<ErrorCode>(error_code);
		
		// Use your existing error_code_name function
		return error_code_name(code);
	}
}

#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
int is_secrets_provisioning_enabled() {
    try {
        std::unique_ptr<Tss2Wrapper> tss2 = std::make_unique<Tss2Wrapper>();
        return tss2->IsKeyPresent() ? 1 : 0;
    }
    catch (TpmError& err) {
        LIBSECRETS_LOG(LogLevel::Error, "IsSecretsProvisioningEnabled\n",
            "TPM error 0x%x: %s\n", err.getReturnCode(), err.getTPMError());
        return -1;
    }
    catch (...) {
        LIBSECRETS_LOG(LogLevel::Error, "IsSecretsProvisioningEnabled\n", "Unknown error\n");
        return -1;
    }
}

#ifdef __cplusplus
}
#endif // __cplusplus
