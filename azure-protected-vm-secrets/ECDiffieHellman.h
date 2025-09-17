// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#ifndef PLATFORM_UNIX
//#include <windows.h>
#include <bcrypt.h>
#else
#endif // !PLATFORM_UNIX
#include <memory>
#include <vector>

template <typename SharedSecret, typename PublicKeyHandle>
class ECDiffieHellman
{
public:
/*
 * Destructor
 */
	virtual ~ECDiffieHellman() = default;
/*
 * Generate a key pair
 */
	virtual void GenerateKeyPair() = 0;
/*
 * Import a private key in PKCS8 format
 * @param derPrivateKey The private key in PKCS8 format
 * @return void
 */
	virtual void ImportPkcs8PrivateKey(std::vector<unsigned char> const&derPrivateKey) = 0;
/*
 * Export a private key in PKCS8 format
 * @return The private key in PKCS8 format
 */
	virtual std::vector<unsigned char> ExportPkcs8PrivateKey() const = 0;
/*
 * Import a public key in SubjectPublicKeyInfo format
 * @param derPublicKey The public key in SubjectPublicKeyInfo format
 * @return void
 */
	virtual void ImportSubjectPublicKeyInfo(std::vector<unsigned char> const&derPublicKey) = 0;
/*
 * Export a public key in SubjectPublicKeyInfo format
 * @return The public key in SubjectPublicKeyInfo format
 */
	virtual std::vector<unsigned char> ExportSubjectPublicKeyInfo() const = 0;
/*
 * Derive a shared secret
 * @param otherParty The other party's public key as an ECDiffieHellman object
 */
	virtual SharedSecret DeriveSecret(ECDiffieHellman &key2) = 0;

/*
 * Get the shared secret handle as a BCRYPT secret handle
 * @return The shared secret handle as a BCRYPT_SECRET_HANDLE
 */
	//virtual GetSharedSecret() const = 0;
/*
 * Get the public key handle as a BCRYPT key handle
 * @return The public key handle as a BCRYPT_KEY_HANDLE
 */
	virtual PublicKeyHandle GetPublicKeyHandle() const = 0;
};