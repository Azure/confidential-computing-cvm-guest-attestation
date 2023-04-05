//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationTypes.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <vector>
#include <stdint.h>

namespace attest
{

enum TpmVersion
{
    V1_2,
    V2_0
};

struct RsaPublicKey
{
    uint16_t bitLength;
    std::vector<unsigned char> exponent;
    std::vector<unsigned char> modulus;
};

#ifndef RsaScheme_enum
#define RsaScheme_enum
// Borrowed from tss2_tpm2_types.h, which is not public
enum RsaScheme : uint16_t
{
    RsaNull = 0x0010, // TPM2_ALG_NULL
    RsaEs = 0x0015,   // TPM2_ALG_RSAES
    RsaOaep = 0x0017, // TPM2_ALG_OAEP
};

enum RsaHashAlg : uint16_t
{
    RsaSha1 = 0x0004,   // TPM2_ALG_SHA1
    RsaSha256 = 0x000B, // TPM2_ALG_SHA256
    RsaSha384 = 0x000C, // TPM2_ALG_SHA384
    RsaSha512 = 0x000D, // TPM2_ALG_SHA512
};
#endif

enum HashAlg
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256
};

using PcrList = std::vector<uint8_t>;
using Buffer = std::vector<unsigned char>;

struct PcrValue
{
    uint8_t index;
    std::vector<unsigned char> digest;
};

struct PcrSet
{
    HashAlg hashAlg;
    std::vector<PcrValue> pcrs;
};

struct PcrQuote
{
    std::vector<unsigned char> quote;
    std::vector<unsigned char> signature;
};

struct EphemeralKey
{
    std::vector<unsigned char> encryptionKey;
    std::vector<unsigned char> certifyInfo;
    std::vector<unsigned char> certifyInfoSignature;
};

} // end attest
