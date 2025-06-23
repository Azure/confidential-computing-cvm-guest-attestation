// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#ifndef PLATFORM_UNIX
//#include <windows.h>
#include <bcrypt.h>
#else
#endif // !PLATFORM_UNIX
#include <vector>
#include <memory>
#include "..\ECDiffieHellman.h"

class BcryptECDiffieHellman : public ECDiffieHellman<BCRYPT_SECRET_HANDLE, BCRYPT_KEY_HANDLE>
{
public:
/*
 * Constructor
 */
	BcryptECDiffieHellman();
/*
 * Constructor
 */
	~BcryptECDiffieHellman();
/*
 * Generate a key pair
 */
	void GenerateKeyPair();
/*
 * Import a private key in PKCS8 format
 * @param derPrivateKey The private key in PKCS8 format
 * @return void
 */
	void ImportPkcs8PrivateKey(std::vector<unsigned char> const&derPrivateKey);
/*
 * Export a private key in PKCS8 format
 * @return The private key in PKCS8 format
 */
	std::vector<unsigned char> ExportPkcs8PrivateKey() const;
/*
 * Import a public key in SubjectPublicKeyInfo format
 * @param derPublicKey The public key in SubjectPublicKeyInfo format
 * @return void
 */
	void ImportSubjectPublicKeyInfo(std::vector<unsigned char> const&derPublicKey);
/*
 * Export a public key in SubjectPublicKeyInfo format
 * @return The public key in SubjectPublicKeyInfo format
 */
	std::vector<unsigned char> ExportSubjectPublicKeyInfo() const;
/*
 * Derive a shared secret
 * @param otherParty The other party's public key as an ECDiffieHellman object
 * @return The shared secret handle as a BCRYPT_SECRET_HANDLE
 */
	BCRYPT_SECRET_HANDLE DeriveSecret(ECDiffieHellman &key2);
/*
 * Get the public key handle as a BCRYPT key handle
 * @return The public key handle as a BCRYPT_KEY_HANDLE
 */
	BCRYPT_KEY_HANDLE GetPublicKeyHandle() const;

private:
	BCRYPT_KEY_HANDLE hEccKeyHandle;
	BCRYPT_SECRET_HANDLE hSharedSecret;
	BCRYPT_ALG_HANDLE hEcHandle;
};