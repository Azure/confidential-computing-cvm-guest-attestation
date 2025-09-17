// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include "../ECDiffieHellman.h"
#include <openssl/evp.h>
#include <vector>

class OsslECDiffieHellman: public ECDiffieHellman<std::vector<unsigned char>, EVP_PKEY*>
{
public:
/*
 * Constructor
 */
	OsslECDiffieHellman();
/*
 * Constructor
 */
	~OsslECDiffieHellman();
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
 */
	std::vector<unsigned char> DeriveSecret(ECDiffieHellman &key2);

/*
 * Get the shared secret handle as a BCRYPT secret handle
 * @return The shared secret handle as a BCRYPT_SECRET_HANDLE
 */
	// std::vector<unsigned char> GetSharedSecret() const;
/*
 * Get the public key handle as a BCRYPT key handle
 * @return The public key handle as a BCRYPT_KEY_HANDLE
 */
	EVP_PKEY* GetPublicKeyHandle() const;

private:
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyPair;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx;
};