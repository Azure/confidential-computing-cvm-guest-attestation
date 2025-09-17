// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "..\pch.h"
#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <iostream>
#include "BcryptHKDF.h"
#include <stdexcept>
#include "..\BcryptError.h"
#include "..\DebugInfo.h"


std::vector<unsigned char> BcryptSha(const std::vector<unsigned char>& data, const size_t hashSize) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg;
	LPCWSTR hashAlg;
    switch (hashSize) {
        case SHA256_HASH_SIZE:
            hashAlg = BCRYPT_SHA256_ALGORITHM;
            break;
        case SHA384_HASH_SIZE:
			hashAlg = BCRYPT_SHA384_ALGORITHM;
            break;
        case SHA512_HASH_SIZE:
			hashAlg = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            throw std::invalid_argument("Unsupported hash size");
    }
	status = BCryptOpenAlgorithmProvider(
		&hAlg, hashAlg,
		NULL, 0);

	std::vector<unsigned char> outputHash(hashSize);

	status = BCryptHash(
		hAlg, NULL, NULL,
		(PUCHAR)data.data(), data.size(),
		outputHash.data(), hashSize);
	if (STATUS_SUCCESS != status) {
		// Handle error
		// CryptoError, Hash subclass, hashError
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw BcryptError(status, "BCryptHash for HMAC failed.\n",
			ErrorCode::CryptographyError_HKDF_extractError);
	}
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return outputHash;
}


BcryptHKDF::BcryptHKDF(BCRYPT_SECRET_HANDLE secret) {
	if (secret == NULL) {
		throw std::invalid_argument("Secret cannot be null.\n");
	}
	this->secret = secret;
	NTSTATUS status;
	status = BCryptOpenAlgorithmProvider(
		&(this->hAlg), BCRYPT_SHA256_ALGORITHM,
		NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (STATUS_SUCCESS != status) {
		// Handle error
		// LibraryError, Bcrypt subclass, providerError
		throw BcryptError(status, "BCryptHash for OpenAlgorithmProvider Failed.\n",
			ErrorCode::LibraryError_Bcrypt_providerError);
	}
}

BcryptHKDF::~BcryptHKDF() {
	if (this->secret != NULL) {
		BCryptDestroySecret(this->secret);

	}
	if (this->hAlg != NULL) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
}

// Derive key based on RFC 5869.
std::vector<unsigned char> BcryptHKDF::DeriveKey(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, size_t keySize) {
	std::vector<unsigned char> prk = Extract(salt);
	return Expand(prk, info, keySize);
}

std::vector<unsigned char> BcryptHKDF::Extract(std::vector<unsigned char> &salt) {
	std::vector<unsigned char> prk;
	NTSTATUS status;
	BCryptBufferDesc params;
	BCryptBuffer buffers[1];
	ULONG prkLength = SHA256_HASH_SIZE;
	ULONG outPrkLength = 0;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = 1;
	params.pBuffers = buffers;
	buffers[0].BufferType = KDF_HASH_ALGORITHM;
	buffers[0].cbBuffer = (ULONG)(wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR);
	buffers[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

	prk = std::vector<unsigned char>(prkLength);
	std::vector<unsigned char> interimPrk(prkLength);

	// Temporary code to first hash the secret. This will be removed once
	// the service derives key material from the hmac.
	status = BCryptDeriveKey(
			this->secret, BCRYPT_KDF_HASH, &params, NULL, 0, &outPrkLength, 0);
	if (status != STATUS_SUCCESS) {
		// CryptoError, HKDF subclass, extractError
		throw BcryptError(status, "BCryptDeriveKey Derive failed.\n",
			ErrorCode::CryptographyError_HKDF_extractError);
	}

	status = BCryptDeriveKey(
		this->secret, BCRYPT_KDF_HASH, &params, interimPrk.data(), interimPrk.size(), &outPrkLength, 0);
	if (status != STATUS_SUCCESS) {
		// CryptoError, HKDF subclass, extractError
		throw BcryptError(status, "BCryptDeriveKey Derive failed.\n",
			ErrorCode::CryptographyError_HKDF_extractError);
	}

	// Calculate the Extracted PRK - HMAC(salt, secret)
	status = BCryptHash(
		this->hAlg, salt.data(), salt.size(),
		interimPrk.data(), interimPrk.size(),
		prk.data(), SHA256_HASH_SIZE);
	if (STATUS_SUCCESS != status) {
		// Handle error
		// CryptoError, HKDF subclass, extractError
		throw BcryptError(status, "BCryptHash for HMAC failed.\n",
			ErrorCode::CryptographyError_HKDF_extractError);
	}
	return prk;
}

std::vector<unsigned char> BcryptHKDF::Expand(std::vector<unsigned char> &prk, std::vector<unsigned char> &info, size_t keySize) {
	BYTE counter = 1;
	std::vector<unsigned char> t;
	std::vector<unsigned char> okm = std::vector<unsigned char>(keySize);
	BCryptBufferDesc params;
	BCryptBuffer buffers[2];
	ULONG okmLength = 0;
	NTSTATUS status = STATUS_SUCCESS;

	//BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;
	BCRYPT_HASH_HANDLE hHash;

	DWORD numRounds = (DWORD)ceil((double)keySize / SHA256_HASH_SIZE);
	std::vector<unsigned char> tBuffer(numRounds * SHA256_HASH_SIZE);
	std::vector<unsigned char> concatBuffer(info.size() + 1 + SHA256_HASH_SIZE);
	DWORD concatBufferSize = 0;
	for (DWORD i = 0; i < numRounds; i++) {
		status = BCryptCreateHash(this->hAlg, &hHash, NULL, 0, prk.data(), prk.size(), 0);
		if (STATUS_SUCCESS != status) {
			// Handle error
			// CryptoError, HKDF subclass, expandError
			throw BcryptError(status, "BCryptCreateHash for HMAC failed.\n",
				ErrorCode::CryptographyError_HKDF_expandError);
		}
		// Prepare the buffer
		concatBufferSize = 0;
		if (i > 0) {
			// Hash the previous T
			status = BCryptHashData(hHash, tBuffer.data() + ((i - 1) * SHA256_HASH_SIZE), SHA256_HASH_SIZE, 0);
			if (STATUS_SUCCESS != status) {
				// Handle error
				// CryptoError, HKDF subclass, expandError
				throw BcryptError(status, "BCryptCreateHash for HMAC failed.\n",
					ErrorCode::CryptographyError_HKDF_expandError);
			}
		}
		// Hash the info
		status = BCryptHashData(hHash, info.data(), info.size(), 0);
		if (STATUS_SUCCESS != status) {
			// Handle error
			// CryptoError, HKDF subclass, expandError
			throw BcryptError(status, "BCryptHash for HMAC failed.\n",
				ErrorCode::CryptographyError_HKDF_expandError);
		}

		// Hash the counter
		status = BCryptHashData(hHash, &counter, 1, 0);
		if (STATUS_SUCCESS != status) {
			// Handle error
			// CryptoError, HKDF subclass, expandError
			throw BcryptError(status, "BCryptHash for HMAC failed.\n",
				ErrorCode::CryptographyError_HKDF_expandError);
		}
		counter++;

		// Finish the hash to the T buffer
		status = BCryptFinishHash(hHash, tBuffer.data() + (i * SHA256_HASH_SIZE), SHA256_HASH_SIZE, 0);
		if (STATUS_SUCCESS != status) {
			// Handle error
			// CryptoError, HKDF subclass, expandError
			throw BcryptError(status, "BCryptHash for HMAC failed.\n",
				ErrorCode::CryptographyError_HKDF_expandError);
		}

		status = BCryptDestroyHash(hHash);
		if (STATUS_SUCCESS != status) {
			// Handle error
			// LibraryError, Bcrypt subclass, handleError
			throw BcryptError(status, "BCryptHash for HMAC failed.\n",
				ErrorCode::LibraryError_Bcrypt_handleError);
		}
	}
	// Copy the first keySize bytes of T buffer to the OKM buffer
	std::copy(tBuffer.data(), tBuffer.data() + keySize, okm.data());

	if (STATUS_SUCCESS != status) {
		// Handle error
		throw BcryptError(status, "BCryptHash for HMAC failed.\n");
	}
	return okm;
}