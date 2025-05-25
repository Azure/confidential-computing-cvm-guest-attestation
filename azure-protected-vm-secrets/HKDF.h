// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <vector>

class HKDF
{
public:
/*
 * Destructor
 */
	virtual ~HKDF() = default;
/*
 * Derive a key based on the HKDF algorithm
 * @param salt The salt to use
 * @param info The info to use for the key derivation
 * @param keySize The size of the key to derive
 * @return The derived key
 */
	virtual std::vector<unsigned char> DeriveKey(std::vector<unsigned char> &salt, std::vector<unsigned char> &info, size_t keySize) = 0;

private:
/*
 * HKDF extract function as per RFC 5869
 */
	virtual std::vector<unsigned char> Extract(std::vector<unsigned char> &salt) = 0;
/*
 * HKDF expand function as per RFC 5869
 */
	virtual std::vector<unsigned char> Expand(std::vector<unsigned char> &prk, std::vector<unsigned char> &info, size_t keySize) = 0;

};