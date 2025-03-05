#pragma once
#ifndef PLATFORM_UNIX
#include <bcrypt.h>
#else
#endif // !PLATFORM_UNIX
#include <vector>
#include "../HKDF.h"

class BcryptHKDF : public HKDF
{
public:
/*
 * Constructor
 */
	BcryptHKDF(BCRYPT_SECRET_HANDLE secret);
/*
 * Destructor
 */
	~BcryptHKDF();
/*
 * Derive a key based on the HKDF algorithm
 * @param salt The salt to use
 * @param info The info to use for the key derivation
 * @param keySize The size of the key to derive
 * @return The derived key
 */
	std::vector<unsigned char> DeriveKey(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, size_t keySize);

private:
/*
 * HKDF extract function as per RFC 5869
 */
	std::vector<unsigned char> Extract(std::vector<unsigned char> &salt);
/*
 * HKDF expand function as per RFC 5869
 */
	std::vector<unsigned char> Expand(std::vector<unsigned char> &prk, std::vector<unsigned char> &info, size_t keySize);
#ifndef PLATFORM_UNIX
	BCRYPT_SECRET_HANDLE secret;
	BCRYPT_ALG_HANDLE hAlg;
#else
#endif // !PLATFORM_UNIX

};