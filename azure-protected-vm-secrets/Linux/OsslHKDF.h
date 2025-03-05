#pragma once
#include <openssl/evp.h>
#include <vector>
#include "../HKDF.h"

class OsslHKDF: public HKDF
{
public:
	/*
	 * Constructor
	 */
	OsslHKDF(const std::vector<unsigned char> &secret);
	/*
	 * Destructor
	 */
	~OsslHKDF();
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
	std::vector<unsigned char> Extract(std::vector<unsigned char> &salt) ;
	/*
	 * HKDF expand function as per RFC 5869
	 */
	std::vector<unsigned char> Expand(std::vector<unsigned char> &prk, std::vector<unsigned char> &info, size_t keySize);

	EVP_PKEY_CTX *pctx;
};